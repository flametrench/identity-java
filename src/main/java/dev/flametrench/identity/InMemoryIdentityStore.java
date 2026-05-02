// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import dev.flametrench.ids.Id;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reference in-memory IdentityStore implementation.
 *
 * <p>Argon2id passwords use {@link PasswordHashing} at the spec floor
 * (m=19456, t=2, p=1). Bearer tokens are 32 random bytes, base64url-
 * encoded; only the SHA-256 hash is persisted, never the token itself.
 *
 * <p>Internally tracks public Credential records alongside type-specific
 * sensitive material (password hashes, passkey public keys) in separate
 * maps so the public surface never leaks them.
 */
public class InMemoryIdentityStore implements IdentityStore {

    private final Map<String, User> users = new LinkedHashMap<>();
    private final Map<String, Credential> credentials = new LinkedHashMap<>();
    private final Map<String, String> passwordHashes = new HashMap<>(); // credId → PHC hash
    private final Map<String, byte[]> passkeyPublicKeys = new HashMap<>();
    /** Natural-key index: "{type}|{identifier}" → credId (active only). */
    private final Map<String, String> activeCredByIdentifier = new HashMap<>();
    private final Map<String, Session> sessions = new LinkedHashMap<>();
    private final Map<String, String> sessionTokenHashes = new HashMap<>(); // sesId → token-hash
    private final Map<String, String> sessionByTokenHash = new HashMap<>(); // token-hash → sesId
    // ─── v0.3 PATs (ADR 0016) ───
    private final Map<String, PersonalAccessToken> pats = new LinkedHashMap<>();
    private final Map<String, String> patSecretHashes = new HashMap<>(); // patId → PHC hash
    private final Map<String, Instant> patLastUsedPersisted = new HashMap<>();
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final long patLastUsedCoalesceSeconds;

    public InMemoryIdentityStore() {
        this(Clock.systemUTC());
    }

    public InMemoryIdentityStore(Clock clock) {
        this(clock, 60L);
    }

    /**
     * @param patLastUsedCoalesceSeconds coalescing window for
     *     {@code lastUsedAt} writes on {@link #verifyPatToken} per
     *     ADR 0016 §"Operational notes". 0 disables coalescing.
     */
    public InMemoryIdentityStore(Clock clock, long patLastUsedCoalesceSeconds) {
        this.clock = clock;
        this.patLastUsedCoalesceSeconds = Math.max(0, patLastUsedCoalesceSeconds);
    }

    private Instant now() {
        return Instant.now(clock);
    }

    private static String identifierKey(CredentialType type, String identifier) {
        return type.getValue() + "|" + identifier;
    }

    private User requireUser(String usrId) {
        User u = users.get(usrId);
        if (u == null) throw new NotFoundError("User " + usrId + " not found");
        return u;
    }

    private Credential requireCredential(String credId) {
        Credential c = credentials.get(credId);
        if (c == null) throw new NotFoundError("Credential " + credId + " not found");
        return c;
    }

    private Session requireSession(String sesId) {
        Session s = sessions.get(sesId);
        if (s == null) throw new NotFoundError("Session " + sesId + " not found");
        return s;
    }

    private void cascadeRevokeSessionsForCredential(String credId) {
        Instant now = now();
        for (Map.Entry<String, Session> e : new ArrayList<>(sessions.entrySet())) {
            Session s = e.getValue();
            if (s.credId().equals(credId) && s.revokedAt() == null) {
                sessions.put(e.getKey(), s.withRevokedAt(now));
                String tokenHash = sessionTokenHashes.remove(e.getKey());
                if (tokenHash != null) sessionByTokenHash.remove(tokenHash);
            }
        }
    }

    private void cascadeRevokeSessionsForUser(String usrId) {
        Instant now = now();
        for (Map.Entry<String, Session> e : new ArrayList<>(sessions.entrySet())) {
            Session s = e.getValue();
            if (s.usrId().equals(usrId) && s.revokedAt() == null) {
                sessions.put(e.getKey(), s.withRevokedAt(now));
                String tokenHash = sessionTokenHashes.remove(e.getKey());
                if (tokenHash != null) sessionByTokenHash.remove(tokenHash);
            }
        }
    }

    private static Credential withCredentialStatus(
            Credential c, Status status, Instant updatedAt
    ) {
        if (c instanceof PasswordCredential p) {
            return new PasswordCredential(
                    p.id(), p.usrId(), p.identifier(), status,
                    p.replaces(), p.createdAt(), updatedAt);
        }
        if (c instanceof PasskeyCredential pk) {
            return new PasskeyCredential(
                    pk.id(), pk.usrId(), pk.identifier(), status,
                    pk.replaces(), pk.passkeySignCount(), pk.passkeyRpId(),
                    pk.createdAt(), updatedAt);
        }
        if (c instanceof OidcCredential o) {
            return new OidcCredential(
                    o.id(), o.usrId(), o.identifier(), status,
                    o.replaces(), o.oidcIssuer(), o.oidcSubject(),
                    o.createdAt(), updatedAt);
        }
        throw new IllegalStateException("Unknown credential variant: " + c.getClass());
    }

    private void ensureUserActiveAndUniqueIdentifier(
            String usrId, CredentialType type, String identifier
    ) {
        User user = requireUser(usrId);
        if (user.status() != Status.ACTIVE) {
            throw new PreconditionError(
                    "Cannot create credentials for " + user.status().getValue() + " user",
                    "user_not_active"
            );
        }
        String key = identifierKey(type, identifier);
        if (activeCredByIdentifier.containsKey(key)) {
            throw new DuplicateCredentialError(
                    "An active " + type.getValue() + " credential already exists for identifier " + identifier
            );
        }
    }

    // ─── Users ───

    @Override
    public User createUser() {
        return createUser(null);
    }

    @Override
    public User createUser(String displayName) {
        Instant now = now();
        User u = new User(Id.generate("usr"), Status.ACTIVE, now, now, displayName);
        users.put(u.id(), u);
        return u;
    }

    @Override
    public User getUser(String usrId) {
        return requireUser(usrId);
    }

    @Override
    public User updateUser(String usrId, String displayName) {
        User u = requireUser(usrId);
        if (u.status() == Status.REVOKED) {
            throw new AlreadyTerminalError("User " + usrId + " is revoked; cannot update");
        }
        String newDisplayName = UNSET.equals(displayName) ? u.displayName() : displayName;
        if (java.util.Objects.equals(newDisplayName, u.displayName())) {
            return u;
        }
        User updated = u.withDisplayName(newDisplayName, now());
        users.put(usrId, updated);
        return updated;
    }

    @Override
    public Page<User> listUsers(String cursor, int limit, String query, Status status) {
        int cappedLimit = Math.max(1, Math.min(limit, 200));
        String needle = query != null ? query.toLowerCase(java.util.Locale.ROOT) : null;
        java.util.List<User> matching = new java.util.ArrayList<>();
        for (User u : users.values()) {
            if (status != null && u.status() != status) continue;
            if (needle != null) {
                boolean hit = false;
                for (Credential c : credentials.values()) {
                    if (!c.usrId().equals(u.id())) continue;
                    if (c.status() != Status.ACTIVE) continue;
                    if (c.identifier().toLowerCase(java.util.Locale.ROOT).contains(needle)) {
                        hit = true;
                        break;
                    }
                }
                if (!hit) continue;
            }
            matching.add(u);
        }
        matching.sort(java.util.Comparator.comparing(User::id));
        int start = 0;
        if (cursor != null) {
            while (start < matching.size() && matching.get(start).id().compareTo(cursor) <= 0) start++;
        }
        int end = Math.min(start + cappedLimit, matching.size());
        java.util.List<User> page = matching.subList(start, end);
        String nextCursor = (start + cappedLimit < matching.size() && !page.isEmpty())
                ? page.get(page.size() - 1).id()
                : null;
        return new Page<>(java.util.List.copyOf(page), nextCursor);
    }

    @Override
    public User suspendUser(String usrId) {
        User u = requireUser(usrId);
        if (u.status() == Status.REVOKED) {
            throw new AlreadyTerminalError("User " + usrId + " is revoked");
        }
        if (u.status() == Status.SUSPENDED) return u;
        Instant now = now();
        User updated = u.withStatus(Status.SUSPENDED, now);
        users.put(usrId, updated);
        cascadeRevokeSessionsForUser(usrId);
        return updated;
    }

    @Override
    public User reinstateUser(String usrId) {
        User u = requireUser(usrId);
        if (u.status() != Status.SUSPENDED) {
            throw new PreconditionError(
                    "User " + usrId + " is " + u.status().getValue()
                            + "; only suspended users can be reinstated",
                    "invalid_transition"
            );
        }
        User updated = u.withStatus(Status.ACTIVE, now());
        users.put(usrId, updated);
        return updated;
    }

    @Override
    public User revokeUser(String usrId) {
        User u = requireUser(usrId);
        if (u.status() == Status.REVOKED) {
            throw new AlreadyTerminalError("User " + usrId + " is already revoked");
        }
        Instant now = now();
        for (Map.Entry<String, Credential> e : new ArrayList<>(credentials.entrySet())) {
            Credential c = e.getValue();
            if (c.usrId().equals(usrId) && c.status() == Status.ACTIVE) {
                credentials.put(e.getKey(), withCredentialStatus(c, Status.REVOKED, now));
                activeCredByIdentifier.remove(identifierKey(c.type(), c.identifier()));
            }
        }
        cascadeRevokeSessionsForUser(usrId);
        User updated = u.withStatus(Status.REVOKED, now);
        users.put(usrId, updated);
        return updated;
    }

    // ─── Credentials ───

    @Override
    public PasswordCredential createPasswordCredential(
            String usrId, String identifier, String password
    ) {
        ensureUserActiveAndUniqueIdentifier(usrId, CredentialType.PASSWORD, identifier);
        Instant now = now();
        String credId = Id.generate("cred");
        String phc = PasswordHashing.hash(password);
        PasswordCredential cred = new PasswordCredential(
                credId, usrId, identifier, Status.ACTIVE, null, now, now);
        credentials.put(credId, cred);
        passwordHashes.put(credId, phc);
        activeCredByIdentifier.put(identifierKey(CredentialType.PASSWORD, identifier), credId);
        return cred;
    }

    @Override
    public PasskeyCredential createPasskeyCredential(
            String usrId, String identifier, byte[] publicKey,
            int signCount, String rpId
    ) {
        ensureUserActiveAndUniqueIdentifier(usrId, CredentialType.PASSKEY, identifier);
        Instant now = now();
        String credId = Id.generate("cred");
        PasskeyCredential cred = new PasskeyCredential(
                credId, usrId, identifier, Status.ACTIVE, null,
                signCount, rpId, now, now);
        credentials.put(credId, cred);
        passkeyPublicKeys.put(credId, publicKey.clone());
        activeCredByIdentifier.put(identifierKey(CredentialType.PASSKEY, identifier), credId);
        return cred;
    }

    @Override
    public OidcCredential createOidcCredential(
            String usrId, String identifier,
            String oidcIssuer, String oidcSubject
    ) {
        ensureUserActiveAndUniqueIdentifier(usrId, CredentialType.OIDC, identifier);
        Instant now = now();
        String credId = Id.generate("cred");
        OidcCredential cred = new OidcCredential(
                credId, usrId, identifier, Status.ACTIVE, null,
                oidcIssuer, oidcSubject, now, now);
        credentials.put(credId, cred);
        activeCredByIdentifier.put(identifierKey(CredentialType.OIDC, identifier), credId);
        return cred;
    }

    @Override
    public Credential getCredential(String credId) {
        return requireCredential(credId);
    }

    @Override
    public List<Credential> listCredentialsForUser(String usrId) {
        List<Credential> out = new ArrayList<>();
        for (Credential c : credentials.values()) {
            if (c.usrId().equals(usrId)) out.add(c);
        }
        return out;
    }

    @Override
    public Credential findCredentialByIdentifier(CredentialType type, String identifier) {
        String credId = activeCredByIdentifier.get(identifierKey(type, identifier));
        return credId == null ? null : requireCredential(credId);
    }

    @Override
    public PasswordCredential rotatePassword(String credId, String newPassword) {
        Credential old = requireCredential(credId);
        if (old.status() != Status.ACTIVE) {
            throw new CredentialNotActiveError(
                    "Credential " + credId + " is " + old.status().getValue());
        }
        if (!(old instanceof PasswordCredential)) {
            throw new CredentialTypeMismatchError(
                    "Cannot rotate " + old.type().getValue() + " credential as password");
        }
        Instant now = now();
        credentials.put(old.id(), withCredentialStatus(old, Status.REVOKED, now));
        activeCredByIdentifier.remove(
                identifierKey(CredentialType.PASSWORD, old.identifier()));
        passwordHashes.remove(old.id());
        cascadeRevokeSessionsForCredential(old.id());
        String newId = Id.generate("cred");
        String phc = PasswordHashing.hash(newPassword);
        PasswordCredential fresh = new PasswordCredential(
                newId, old.usrId(), old.identifier(), Status.ACTIVE,
                old.id(), now, now);
        credentials.put(newId, fresh);
        passwordHashes.put(newId, phc);
        activeCredByIdentifier.put(
                identifierKey(CredentialType.PASSWORD, old.identifier()), newId);
        return fresh;
    }

    @Override
    public PasskeyCredential rotatePasskey(
            String credId, byte[] publicKey, int signCount, String rpId
    ) {
        Credential old = requireCredential(credId);
        if (old.status() != Status.ACTIVE) {
            throw new CredentialNotActiveError(
                    "Credential " + credId + " is " + old.status().getValue());
        }
        if (!(old instanceof PasskeyCredential)) {
            throw new CredentialTypeMismatchError(
                    "Cannot rotate " + old.type().getValue() + " credential as passkey");
        }
        Instant now = now();
        credentials.put(old.id(), withCredentialStatus(old, Status.REVOKED, now));
        activeCredByIdentifier.remove(
                identifierKey(CredentialType.PASSKEY, old.identifier()));
        passkeyPublicKeys.remove(old.id());
        cascadeRevokeSessionsForCredential(old.id());
        String newId = Id.generate("cred");
        PasskeyCredential fresh = new PasskeyCredential(
                newId, old.usrId(), old.identifier(), Status.ACTIVE,
                old.id(), signCount, rpId, now, now);
        credentials.put(newId, fresh);
        passkeyPublicKeys.put(newId, publicKey.clone());
        activeCredByIdentifier.put(
                identifierKey(CredentialType.PASSKEY, old.identifier()), newId);
        return fresh;
    }

    @Override
    public OidcCredential rotateOidc(
            String credId, String oidcIssuer, String oidcSubject
    ) {
        Credential old = requireCredential(credId);
        if (old.status() != Status.ACTIVE) {
            throw new CredentialNotActiveError(
                    "Credential " + credId + " is " + old.status().getValue());
        }
        if (!(old instanceof OidcCredential)) {
            throw new CredentialTypeMismatchError(
                    "Cannot rotate " + old.type().getValue() + " credential as oidc");
        }
        Instant now = now();
        credentials.put(old.id(), withCredentialStatus(old, Status.REVOKED, now));
        activeCredByIdentifier.remove(
                identifierKey(CredentialType.OIDC, old.identifier()));
        cascadeRevokeSessionsForCredential(old.id());
        String newId = Id.generate("cred");
        OidcCredential fresh = new OidcCredential(
                newId, old.usrId(), old.identifier(), Status.ACTIVE,
                old.id(), oidcIssuer, oidcSubject, now, now);
        credentials.put(newId, fresh);
        activeCredByIdentifier.put(
                identifierKey(CredentialType.OIDC, old.identifier()), newId);
        return fresh;
    }

    @Override
    public Credential suspendCredential(String credId) {
        Credential c = requireCredential(credId);
        if (c.status() != Status.ACTIVE) {
            throw new PreconditionError(
                    "Credential " + credId + " is " + c.status().getValue()
                            + "; only active credentials can be suspended",
                    "cred_not_active"
            );
        }
        Instant now = now();
        Credential updated = withCredentialStatus(c, Status.SUSPENDED, now);
        credentials.put(credId, updated);
        activeCredByIdentifier.remove(identifierKey(c.type(), c.identifier()));
        cascadeRevokeSessionsForCredential(credId);
        return updated;
    }

    @Override
    public Credential reinstateCredential(String credId) {
        Credential c = requireCredential(credId);
        if (c.status() != Status.SUSPENDED) {
            throw new PreconditionError(
                    "Credential " + credId + " is " + c.status().getValue()
                            + "; only suspended credentials can be reinstated",
                    "invalid_transition"
            );
        }
        String key = identifierKey(c.type(), c.identifier());
        if (activeCredByIdentifier.containsKey(key)) {
            throw new DuplicateCredentialError(
                    "Another active " + c.type().getValue()
                            + " credential already exists for " + c.identifier()
                            + "; cannot reinstate"
            );
        }
        Instant now = now();
        Credential updated = withCredentialStatus(c, Status.ACTIVE, now);
        credentials.put(credId, updated);
        activeCredByIdentifier.put(key, credId);
        return updated;
    }

    @Override
    public Credential revokeCredential(String credId) {
        Credential c = requireCredential(credId);
        if (c.status() == Status.REVOKED) {
            throw new AlreadyTerminalError("Credential " + credId + " is already revoked");
        }
        Instant now = now();
        Credential updated = withCredentialStatus(c, Status.REVOKED, now);
        credentials.put(credId, updated);
        activeCredByIdentifier.remove(identifierKey(c.type(), c.identifier()));
        cascadeRevokeSessionsForCredential(credId);
        return updated;
    }

    @Override
    public VerifiedCredential verifyPassword(String identifier, String password) {
        String credId = activeCredByIdentifier.get(
                identifierKey(CredentialType.PASSWORD, identifier));
        if (credId == null) {
            throw new InvalidCredentialError();
        }
        Credential cred = requireCredential(credId);
        if (!(cred instanceof PasswordCredential)) {
            throw new InvalidCredentialError();
        }
        String phc = passwordHashes.get(credId);
        if (phc == null || !PasswordHashing.verify(phc, password)) {
            throw new InvalidCredentialError();
        }
        // ADR 0008: surface usr_mfa_policy state.
        UserMfaPolicy policy = mfaPolicies.get(cred.usrId());
        boolean mfaRequired = false;
        if (policy != null && policy.required()) {
            if (policy.graceUntil() == null || !policy.graceUntil().isAfter(now())) {
                mfaRequired = true;
            }
        }
        return new VerifiedCredential(cred.usrId(), cred.id(), mfaRequired);
    }

    // ─── Sessions ───

    private String generateToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String hashToken(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(token.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) return false;
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public SessionWithToken createSession(String usrId, String credId, long ttlSeconds) {
        User user = requireUser(usrId);
        if (user.status() != Status.ACTIVE) {
            throw new PreconditionError(
                    "Cannot create session for " + user.status().getValue() + " user",
                    "user_not_active"
            );
        }
        Credential cred = requireCredential(credId);
        if (cred.status() != Status.ACTIVE) {
            throw new CredentialNotActiveError(
                    "Credential " + credId + " is " + cred.status().getValue());
        }
        if (!cred.usrId().equals(usrId)) {
            throw new PreconditionError(
                    "Credential " + credId + " does not belong to " + usrId,
                    "cred_user_mismatch"
            );
        }
        if (ttlSeconds < 60) {
            throw new PreconditionError("ttlSeconds must be >= 60", "ttl_too_short");
        }
        Instant now = now();
        String token = generateToken();
        String tokenHash = hashToken(token);
        Session session = new Session(
                Id.generate("ses"), usrId, credId,
                now, now.plusSeconds(ttlSeconds), null);
        sessions.put(session.id(), session);
        sessionTokenHashes.put(session.id(), tokenHash);
        sessionByTokenHash.put(tokenHash, session.id());
        return new SessionWithToken(session, token);
    }

    @Override
    public Session getSession(String sesId) {
        return requireSession(sesId);
    }

    @Override
    public Page<Session> listSessionsForUser(String usrId, String cursor, int limit) {
        List<Session> matching = new ArrayList<>();
        for (Session s : sessions.values()) {
            if (s.usrId().equals(usrId)) matching.add(s);
        }
        matching.sort(Comparator.comparing(Session::id));
        int start = 0;
        if (cursor != null) {
            for (int i = 0; i < matching.size(); i++) {
                if (matching.get(i).id().compareTo(cursor) > 0) {
                    start = i;
                    break;
                }
                start = i + 1;
            }
        }
        int end = Math.min(start + limit, matching.size());
        List<Session> slice = matching.subList(start, end);
        String nextCursor = (start + limit) < matching.size() && !slice.isEmpty()
                ? slice.get(slice.size() - 1).id()
                : null;
        return new Page<>(new ArrayList<>(slice), nextCursor);
    }

    @Override
    public Session verifySessionToken(String token) {
        String tokenHash = hashToken(token);
        String sesId = sessionByTokenHash.get(tokenHash);
        if (sesId == null) throw new InvalidTokenError();
        Session session = requireSession(sesId);
        String storedHash = sessionTokenHashes.getOrDefault(sesId, "");
        if (!constantTimeEquals(tokenHash, storedHash)) {
            throw new InvalidTokenError();
        }
        if (session.revokedAt() != null) {
            throw new SessionExpiredError("Session is revoked");
        }
        if (now().isAfter(session.expiresAt())) {
            throw new SessionExpiredError("Session has expired");
        }
        return session;
    }

    @Override
    public SessionWithToken refreshSession(String sesId) {
        Session session = requireSession(sesId);
        if (session.revokedAt() != null) {
            throw new SessionExpiredError("Session is already revoked");
        }
        if (now().isAfter(session.expiresAt())) {
            throw new SessionExpiredError("Session has expired");
        }
        Instant now = now();
        sessions.put(sesId, session.withRevokedAt(now));
        String oldHash = sessionTokenHashes.remove(sesId);
        if (oldHash != null) sessionByTokenHash.remove(oldHash);
        Duration ttl = Duration.between(session.createdAt(), session.expiresAt());
        String token = generateToken();
        String tokenHash = hashToken(token);
        Session fresh = new Session(
                Id.generate("ses"), session.usrId(), session.credId(),
                now, now.plus(ttl), null);
        sessions.put(fresh.id(), fresh);
        sessionTokenHashes.put(fresh.id(), tokenHash);
        sessionByTokenHash.put(tokenHash, fresh.id());
        return new SessionWithToken(fresh, token);
    }

    @Override
    public Session revokeSession(String sesId) {
        Session session = requireSession(sesId);
        if (session.revokedAt() != null) return session;
        Instant now = now();
        Session updated = session.withRevokedAt(now);
        sessions.put(sesId, updated);
        String oldHash = sessionTokenHashes.remove(sesId);
        if (oldHash != null) sessionByTokenHash.remove(oldHash);
        return updated;
    }

    // ─── v0.2 MFA store operations (ADR 0008) ───

    /** Pending TOTP/WebAuthn factor TTL per ADR 0008. */
    public static final long PENDING_FACTOR_TTL_SECONDS = 600L;

    private final java.util.Map<String, Factor> mfaFactors = new java.util.HashMap<>();
    private final java.util.Map<String, byte[]> mfaTotpSecrets = new java.util.HashMap<>();
    private final java.util.Map<String, byte[]> mfaWebauthnKeys = new java.util.HashMap<>();
    private final java.util.Map<String, java.util.List<String>> mfaRecoveryHashes = new java.util.HashMap<>();
    private final java.util.Map<String, boolean[]> mfaRecoveryConsumed = new java.util.HashMap<>();
    /** Singleton index "{usrId}|{type}" → mfaId; covers TOTP + recovery. */
    private final java.util.Map<String, String> mfaActiveSingleton = new java.util.HashMap<>();
    private final java.util.Map<String, String> mfaWebauthnByCredentialId = new java.util.HashMap<>();
    private final java.util.Map<String, UserMfaPolicy> mfaPolicies = new java.util.HashMap<>();

    @Override
    public TotpEnrollmentResult enrollTotpFactor(String usrId, String identifier) {
        checkUserActive(usrId);
        enforceNoActiveSingleton(usrId, "totp");
        Instant now = now();
        byte[] secret = Totp.generateSecret();
        String mfaId = Id.generate("mfa");
        TotpFactor factor = new TotpFactor(
                mfaId, usrId, identifier,
                FactorStatus.PENDING, null, now, now);
        mfaFactors.put(mfaId, factor);
        mfaTotpSecrets.put(mfaId, secret);
        return new TotpEnrollmentResult(
                factor,
                base32Encode(secret).replaceAll("=+$", ""),
                Totp.otpauthUri(secret, identifier, "Flametrench"));
    }

    @Override
    public WebAuthnEnrollmentResult enrollWebAuthnFactor(
            String usrId, String identifier,
            byte[] publicKey, long signCount, String rpId) {
        checkUserActive(usrId);
        if (mfaWebauthnByCredentialId.containsKey(identifier)) {
            throw new PreconditionError(
                    "WebAuthn credential '" + identifier + "' is already enrolled",
                    "duplicate_webauthn_credential");
        }
        Instant now = now();
        String mfaId = Id.generate("mfa");
        WebAuthnFactor factor = new WebAuthnFactor(
                mfaId, usrId, identifier,
                FactorStatus.PENDING, null,
                rpId, signCount, now, now);
        mfaFactors.put(mfaId, factor);
        mfaWebauthnKeys.put(mfaId, publicKey);
        mfaWebauthnByCredentialId.put(identifier, mfaId);
        return new WebAuthnEnrollmentResult(factor);
    }

    @Override
    public RecoveryEnrollmentResult enrollRecoveryFactor(String usrId) {
        checkUserActive(usrId);
        enforceNoActiveSingleton(usrId, "recovery");
        Instant now = now();
        String[] codes = RecoveryCodes.generateSet();
        java.util.List<String> hashes = new java.util.ArrayList<>(codes.length);
        for (String c : codes) hashes.add(PasswordHashing.hash(c));
        boolean[] consumed = new boolean[codes.length];
        String mfaId = Id.generate("mfa");
        RecoveryFactor factor = new RecoveryFactor(
                mfaId, usrId, FactorStatus.ACTIVE, null, now, now, codes.length);
        mfaFactors.put(mfaId, factor);
        mfaRecoveryHashes.put(mfaId, hashes);
        mfaRecoveryConsumed.put(mfaId, consumed);
        mfaActiveSingleton.put(usrId + "|recovery", mfaId);
        return new RecoveryEnrollmentResult(factor, java.util.List.of(codes));
    }

    @Override
    public Factor getMfaFactor(String mfaId) {
        return requireFactor(mfaId);
    }

    @Override
    public java.util.List<Factor> listMfaFactors(String usrId) {
        java.util.List<Factor> out = new java.util.ArrayList<>();
        for (Factor f : mfaFactors.values()) {
            if (f.usrId().equals(usrId)) out.add(f);
        }
        return out;
    }

    @Override
    public TotpFactor confirmTotpFactor(String mfaId, String code) {
        Factor f = requireFactor(mfaId);
        if (!(f instanceof TotpFactor totp)) {
            throw new CredentialTypeMismatchError("Factor " + mfaId + " is not totp");
        }
        if (totp.status() != FactorStatus.PENDING) {
            throw new PreconditionError(
                    "Factor " + mfaId + " is " + totp.status().getValue() + "; only pending factors confirm",
                    "factor_not_pending");
        }
        checkPendingNotExpired(totp);
        byte[] secret = mfaTotpSecrets.get(mfaId);
        if (!Totp.verify(secret, code, now().getEpochSecond(),
                Totp.DEFAULT_PERIOD, Totp.DEFAULT_DIGITS, Totp.DEFAULT_ALGORITHM, 1)) {
            throw new InvalidCredentialError("TOTP code did not verify");
        }
        Instant now = now();
        TotpFactor active = new TotpFactor(
                totp.id(), totp.usrId(), totp.identifier(),
                FactorStatus.ACTIVE, totp.replaces(),
                totp.createdAt(), now);
        mfaFactors.put(mfaId, active);
        mfaActiveSingleton.put(totp.usrId() + "|totp", mfaId);
        return active;
    }

    @Override
    public WebAuthnFactor confirmWebAuthnFactor(
            String mfaId,
            byte[] authenticatorData, byte[] clientDataJson, byte[] signature,
            byte[] expectedChallenge, String expectedOrigin) {
        Factor f = requireFactor(mfaId);
        if (!(f instanceof WebAuthnFactor wa)) {
            throw new CredentialTypeMismatchError("Factor " + mfaId + " is not webauthn");
        }
        if (wa.status() != FactorStatus.PENDING) {
            throw new PreconditionError(
                    "Factor " + mfaId + " is " + wa.status().getValue() + "; only pending factors confirm",
                    "factor_not_pending");
        }
        checkPendingNotExpired(wa);
        WebAuthnAssertionResult result = WebAuthn.verifyAssertion(
                mfaWebauthnKeys.get(mfaId),
                wa.signCount(),
                wa.rpId(),
                expectedChallenge,
                expectedOrigin,
                authenticatorData,
                clientDataJson,
                signature);
        Instant now = now();
        WebAuthnFactor active = new WebAuthnFactor(
                wa.id(), wa.usrId(), wa.identifier(),
                FactorStatus.ACTIVE, wa.replaces(),
                wa.rpId(), result.newSignCount(),
                wa.createdAt(), now);
        mfaFactors.put(mfaId, active);
        return active;
    }

    @Override
    public Factor revokeMfaFactor(String mfaId) {
        Factor f = requireFactor(mfaId);
        if (f.status() == FactorStatus.REVOKED) return f;
        Instant now = now();
        Factor revoked;
        if (f instanceof TotpFactor t) {
            revoked = new TotpFactor(t.id(), t.usrId(), t.identifier(),
                    FactorStatus.REVOKED, t.replaces(), t.createdAt(), now);
            mfaActiveSingleton.remove(t.usrId() + "|totp");
        } else if (f instanceof WebAuthnFactor w) {
            revoked = new WebAuthnFactor(w.id(), w.usrId(), w.identifier(),
                    FactorStatus.REVOKED, w.replaces(),
                    w.rpId(), w.signCount(), w.createdAt(), now);
            mfaWebauthnByCredentialId.remove(w.identifier());
        } else if (f instanceof RecoveryFactor r) {
            revoked = new RecoveryFactor(r.id(), r.usrId(),
                    FactorStatus.REVOKED, r.replaces(),
                    r.createdAt(), now, r.remaining());
            mfaActiveSingleton.remove(r.usrId() + "|recovery");
        } else {
            throw new IllegalStateException("Unknown factor type");
        }
        mfaFactors.put(mfaId, revoked);
        return revoked;
    }

    @Override
    public MfaVerifyResult verifyMfa(String usrId, MfaProof proof) {
        if (proof instanceof TotpProof t) return verifyTotp(usrId, t.code());
        if (proof instanceof WebAuthnProof w) return verifyWebAuthnProof(usrId, w);
        if (proof instanceof RecoveryProof r) return verifyRecovery(usrId, r.code());
        throw new IllegalArgumentException("Unknown proof type");
    }

    private MfaVerifyResult verifyTotp(String usrId, String code) {
        String mfaId = mfaActiveSingleton.get(usrId + "|totp");
        if (mfaId == null) {
            throw new InvalidCredentialError("No active TOTP factor for user");
        }
        byte[] secret = mfaTotpSecrets.get(mfaId);
        if (!Totp.verify(secret, code, now().getEpochSecond(),
                Totp.DEFAULT_PERIOD, Totp.DEFAULT_DIGITS, Totp.DEFAULT_ALGORITHM, 1)) {
            throw new InvalidCredentialError("TOTP code did not verify");
        }
        return new MfaVerifyResult(mfaId, FactorType.TOTP, now(), null);
    }

    private MfaVerifyResult verifyWebAuthnProof(String usrId, WebAuthnProof proof) {
        String mfaId = mfaWebauthnByCredentialId.get(proof.credentialId());
        if (mfaId == null) {
            throw new InvalidCredentialError("No WebAuthn factor for credential id");
        }
        Factor f = mfaFactors.get(mfaId);
        if (!(f instanceof WebAuthnFactor wa)) {
            throw new InvalidCredentialError("Factor is not WebAuthn");
        }
        if (!wa.usrId().equals(usrId)) {
            throw new InvalidCredentialError("WebAuthn factor does not belong to user");
        }
        if (wa.status() != FactorStatus.ACTIVE) {
            throw new InvalidCredentialError("WebAuthn factor is " + wa.status().getValue() + ", not active");
        }
        WebAuthnAssertionResult result = WebAuthn.verifyAssertion(
                mfaWebauthnKeys.get(mfaId),
                wa.signCount(), wa.rpId(),
                proof.expectedChallenge(), proof.expectedOrigin(),
                proof.authenticatorData(), proof.clientDataJson(), proof.signature());
        Instant now = now();
        mfaFactors.put(mfaId, new WebAuthnFactor(
                wa.id(), wa.usrId(), wa.identifier(),
                wa.status(), wa.replaces(),
                wa.rpId(), result.newSignCount(),
                wa.createdAt(), now));
        return new MfaVerifyResult(mfaId, FactorType.WEBAUTHN, now, result.newSignCount());
    }

    private MfaVerifyResult verifyRecovery(String usrId, String code) {
        String mfaId = mfaActiveSingleton.get(usrId + "|recovery");
        if (mfaId == null) {
            throw new InvalidCredentialError("No active recovery factor for user");
        }
        String normalized = RecoveryCodes.normalizeInput(code);
        if (!RecoveryCodes.isValid(normalized)) {
            throw new InvalidCredentialError("Recovery code is malformed");
        }
        java.util.List<String> hashes = mfaRecoveryHashes.get(mfaId);
        boolean[] consumed = mfaRecoveryConsumed.get(mfaId);
        // Walk every active slot regardless of an early match — keeps work
        // constant relative to the active set so timing doesn't leak which
        // slot matched.
        int matchedSlot = -1;
        for (int i = 0; i < hashes.size(); i++) {
            if (consumed[i]) continue;
            if (PasswordHashing.verify(hashes.get(i), normalized) && matchedSlot == -1) {
                matchedSlot = i;
            }
        }
        if (matchedSlot == -1) {
            throw new InvalidCredentialError("Recovery code did not verify");
        }
        consumed[matchedSlot] = true;
        Factor f = mfaFactors.get(mfaId);
        if (f instanceof RecoveryFactor r) {
            int remaining = 0;
            for (boolean c : consumed) if (!c) remaining++;
            mfaFactors.put(mfaId, new RecoveryFactor(
                    r.id(), r.usrId(), r.status(), r.replaces(),
                    r.createdAt(), now(), remaining));
        }
        return new MfaVerifyResult(mfaId, FactorType.RECOVERY, now(), null);
    }

    @Override
    public UserMfaPolicy getMfaPolicy(String usrId) {
        requireUser(usrId);
        return mfaPolicies.get(usrId);
    }

    @Override
    public UserMfaPolicy setMfaPolicy(String usrId, boolean required, Instant graceUntil) {
        requireUser(usrId);
        UserMfaPolicy policy = new UserMfaPolicy(usrId, required, graceUntil, now());
        mfaPolicies.put(usrId, policy);
        return policy;
    }

    // ─── private helpers ───

    private Factor requireFactor(String mfaId) {
        Factor f = mfaFactors.get(mfaId);
        if (f == null) throw new NotFoundError("MFA factor " + mfaId + " not found");
        return f;
    }

    private void checkUserActive(String usrId) {
        User user = requireUser(usrId);
        if (user.status() != Status.ACTIVE) {
            throw new PreconditionError(
                    "User " + usrId + " is " + user.status().getValue() + "; cannot enroll MFA",
                    "user_not_active");
        }
    }

    private void enforceNoActiveSingleton(String usrId, String type) {
        if (mfaActiveSingleton.containsKey(usrId + "|" + type)) {
            throw new PreconditionError(
                    "User " + usrId + " already has an active " + type + " factor; "
                            + "revoke before re-enrolling",
                    "active_singleton_exists");
        }
    }

    private void checkPendingNotExpired(Factor factor) {
        if (factor.status() != FactorStatus.PENDING) return;
        long ageSec = java.time.Duration.between(factor.createdAt(), now()).getSeconds();
        if (ageSec > PENDING_FACTOR_TTL_SECONDS) {
            throw new PreconditionError(
                    "Pending factor " + factor.id() + " expired ("
                            + ageSec + "s > " + PENDING_FACTOR_TTL_SECONDS + "s)",
                    "pending_factor_expired");
        }
    }

    /** Inline RFC 4648 base32 (matches Python SDK's otpauth URI). */
    private static String base32Encode(byte[] buf) {
        char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
        int bits = 0, value = 0;
        StringBuilder out = new StringBuilder();
        for (byte b : buf) {
            value = (value << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                out.append(alphabet[(value >>> (bits - 5)) & 0x1F]);
                bits -= 5;
            }
        }
        if (bits > 0) {
            out.append(alphabet[(value << (5 - bits)) & 0x1F]);
        }
        return out.toString();
    }

    // ─── v0.3 personal access tokens (ADR 0016) ───

    private static final java.util.regex.Pattern PAT_HEX_PATTERN =
            java.util.regex.Pattern.compile("[0-9a-f]{32}");

    @Override
    public CreatePatResult createPat(String usrId, String name, java.util.List<String> scope, Instant expiresAt) {
        User u = requireUser(usrId);
        if (u.status() == Status.REVOKED) {
            throw new AlreadyTerminalError("User " + usrId + " is revoked; cannot issue PATs");
        }
        if (name == null || name.length() < 1 || name.length() > 120) {
            int len = name == null ? 0 : name.length();
            throw new PreconditionError(
                    "PAT name must be 1–120 characters (got " + len + ")",
                    "pat.name_invalid");
        }
        Instant now = now();
        if (expiresAt != null && !expiresAt.isAfter(now)) {
            throw new PreconditionError(
                    "PAT expires_at must be strictly in the future",
                    "pat.expires_in_past");
        }
        // security-audit-v0.3.md H1: 365-day cap from ADR 0016 §"Constraints".
        if (expiresAt != null
                && (expiresAt.getEpochSecond() - now.getEpochSecond())
                        > PatLimits.MAX_LIFETIME_SECONDS) {
            throw new PreconditionError(
                    "PAT expires_at exceeds the spec cap of "
                            + PatLimits.MAX_LIFETIME_SECONDS
                            + " seconds (365 days) from creation",
                    "pat.expires_too_far");
        }
        String patId = dev.flametrench.ids.Id.generate("pat");
        String idHexSegment = patId.substring(4); // strip 'pat_'
        byte[] secretBytes = new byte[32];
        random.nextBytes(secretBytes);
        String secretSegment = base64UrlEncode(secretBytes);
        String token = "pat_" + idHexSegment + "_" + secretSegment;
        String secretHash = PasswordHashing.hash(secretSegment);
        java.util.List<String> scopeCopy = scope == null
                ? java.util.List.of()
                : java.util.List.copyOf(scope);

        PersonalAccessToken pat = new PersonalAccessToken(
                patId, usrId, name, scopeCopy, PatStatus.ACTIVE,
                expiresAt, null, null, now, now);
        pats.put(patId, pat);
        patSecretHashes.put(patId, secretHash);
        return new CreatePatResult(pat, token);
    }

    @Override
    public PersonalAccessToken getPat(String patId) {
        PersonalAccessToken pat = pats.get(patId);
        if (pat == null) throw new NotFoundError("PAT " + patId + " not found");
        return withDerivedStatus(pat);
    }

    @Override
    public Page<PersonalAccessToken> listPatsForUser(String usrId, String cursor, int limit, PatStatus status) {
        int effectiveLimit = Math.max(1, Math.min(limit, 200));
        java.util.List<PersonalAccessToken> matching = new ArrayList<>();
        for (PersonalAccessToken pat : pats.values()) {
            if (!pat.usrId().equals(usrId)) continue;
            PersonalAccessToken derived = withDerivedStatus(pat);
            if (status != null && derived.status() != status) continue;
            matching.add(derived);
        }
        matching.sort(java.util.Comparator.comparing(PersonalAccessToken::id));
        int startIdx = 0;
        if (cursor != null) {
            for (int i = 0; i < matching.size(); i++) {
                if (matching.get(i).id().compareTo(cursor) > 0) {
                    startIdx = i;
                    break;
                }
                startIdx = i + 1;
            }
        }
        int endIdx = Math.min(startIdx + effectiveLimit, matching.size());
        java.util.List<PersonalAccessToken> slice = matching.subList(startIdx, endIdx);
        String nextCursor = (startIdx + effectiveLimit) < matching.size() && !slice.isEmpty()
                ? slice.get(slice.size() - 1).id()
                : null;
        return new Page<>(java.util.List.copyOf(slice), nextCursor);
    }

    @Override
    public PersonalAccessToken revokePat(String patId) {
        PersonalAccessToken pat = pats.get(patId);
        if (pat == null) throw new NotFoundError("PAT " + patId + " not found");
        if (pat.revokedAt() != null) {
            return withDerivedStatus(pat);
        }
        Instant now = now();
        PersonalAccessToken updated = new PersonalAccessToken(
                pat.id(), pat.usrId(), pat.name(), pat.scope(),
                PatStatus.REVOKED,
                pat.expiresAt(), pat.lastUsedAt(), now,
                pat.createdAt(), now);
        pats.put(patId, updated);
        return updated;
    }

    @Override
    public VerifiedPat verifyPatToken(String token) {
        // Step 1–2: structural decode.
        if (token == null || !token.startsWith("pat_")) {
            throw new InvalidPatTokenError();
        }
        if (token.length() < 4 + 32 + 1 + 1) {
            throw new InvalidPatTokenError();
        }
        String idHex = token.substring(4, 36);
        if (!PAT_HEX_PATTERN.matcher(idHex).matches()) {
            throw new InvalidPatTokenError();
        }
        if (token.charAt(36) != '_') {
            throw new InvalidPatTokenError();
        }
        String secretSegment = token.substring(37);
        if (secretSegment.isEmpty()) {
            throw new InvalidPatTokenError();
        }
        String patId = "pat_" + idHex;

        // Step 3–4: lookup; conflate "no row" with "wrong secret".
        // security-audit-v0.3.md H2: when the row is missing we still
        // perform an Argon2id verify against a dummy hash so the
        // wall-clock time of "no such pat_id" matches the
        // row-exists-but-wrong-secret path.
        PersonalAccessToken pat = pats.get(patId);
        if (pat == null) {
            PasswordHashing.verify(PatLimits.DUMMY_PHC_HASH, secretSegment);
            throw new InvalidPatTokenError();
        }
        // Step 5: revoked terminal check.
        if (pat.revokedAt() != null) throw new PatRevokedError(patId);
        // Step 6: expiry.
        Instant now = now();
        if (pat.expiresAt() != null && !pat.expiresAt().isAfter(now)) {
            throw new PatExpiredError(patId);
        }
        // Step 7: Argon2id verify; conflated error shape.
        String hash = patSecretHashes.get(patId);
        if (hash == null || !PasswordHashing.verify(hash, secretSegment)) {
            throw new InvalidPatTokenError();
        }
        // Step 8: lastUsedAt update with coalescing.
        Instant persisted = patLastUsedPersisted.get(patId);
        boolean shouldUpdate = persisted == null
                || patLastUsedCoalesceSeconds == 0
                || (now.getEpochSecond() - persisted.getEpochSecond()) >= patLastUsedCoalesceSeconds;
        if (shouldUpdate) {
            pats.put(patId, new PersonalAccessToken(
                    pat.id(), pat.usrId(), pat.name(), pat.scope(),
                    pat.status(),
                    pat.expiresAt(), now, pat.revokedAt(),
                    pat.createdAt(), now));
            patLastUsedPersisted.put(patId, now);
        }
        return new VerifiedPat(patId, pat.usrId(), java.util.List.copyOf(pat.scope()));
    }

    private PersonalAccessToken withDerivedStatus(PersonalAccessToken pat) {
        PatStatus derived;
        if (pat.revokedAt() != null) {
            derived = PatStatus.REVOKED;
        } else if (pat.expiresAt() != null && !pat.expiresAt().isAfter(now())) {
            derived = PatStatus.EXPIRED;
        } else {
            derived = PatStatus.ACTIVE;
        }
        if (derived == pat.status()) return pat;
        return new PersonalAccessToken(
                pat.id(), pat.usrId(), pat.name(), pat.scope(),
                derived,
                pat.expiresAt(), pat.lastUsedAt(), pat.revokedAt(),
                pat.createdAt(), pat.updatedAt());
    }

    /** RFC 4648 §5 base64url, no padding. Matches the spec wire format. */
    private static String base64UrlEncode(byte[] buf) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
