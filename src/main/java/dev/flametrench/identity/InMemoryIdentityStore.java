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
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public InMemoryIdentityStore() {
        this(Clock.systemUTC());
    }

    public InMemoryIdentityStore(Clock clock) {
        this.clock = clock;
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
        Instant now = now();
        User u = new User(Id.generate("usr"), Status.ACTIVE, now, now);
        users.put(u.id(), u);
        return u;
    }

    @Override
    public User getUser(String usrId) {
        return requireUser(usrId);
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
        return new VerifiedCredential(cred.usrId(), cred.id());
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
}
