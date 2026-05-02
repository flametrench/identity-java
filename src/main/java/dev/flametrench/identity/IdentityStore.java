// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.util.List;

/**
 * Contract every identity backend implements.
 *
 * <p>Cascade guarantees (spec-required):
 * <ul>
 *   <li>Revoking a user revokes every active credential AND terminates
 *       every active session.</li>
 *   <li>Suspending a user terminates active sessions but preserves
 *       credentials.</li>
 *   <li>Rotating a credential terminates every session bound to the old
 *       credential.</li>
 *   <li>Revoking or suspending a credential terminates every session
 *       bound to it.</li>
 * </ul>
 */
public interface IdentityStore {

    /**
     * Sentinel for {@link #updateUser} partial-update semantics (ADR 0014).
     * Pass this constant to skip a field (its value is preserved); pass
     * {@code null} to clear the field.
     */
    String UNSET = "__flametrench_unset__";

    // ─── Users ───
    /** v0.1-compatible 0-arg createUser. Defaults displayName to null. */
    User createUser();
    /** v0.2 (ADR 0014) createUser accepting an optional displayName. */
    User createUser(String displayName);
    User getUser(String usrId);
    /**
     * ADR 0014 partial update of v0.2 user metadata.
     *
     * <p>Pass {@link #UNSET} to skip the field; pass {@code null} to
     * clear it. Updating a revoked user raises
     * {@link AlreadyTerminalError}; an unknown id raises
     * {@link NotFoundError}.
     */
    User updateUser(String usrId, String displayName);
    /**
     * ADR 0015 — paginated user enumeration. Adopters MUST gate the call
     * site (sysadmin route or equivalent); the SDK does not enforce
     * authorization. Cursor and ordering match listMembers.
     *
     * @param cursor opaque cursor; null for the first page
     * @param limit  page size; clamped to [1, 200]
     * @param query  case-insensitive substring against active credential identifiers; null for no filter
     * @param status user-status filter; null for all
     */
    Page<User> listUsers(String cursor, int limit, String query, Status status);
    User suspendUser(String usrId);
    User reinstateUser(String usrId);
    User revokeUser(String usrId);

    // ─── Credentials ───
    PasswordCredential createPasswordCredential(
            String usrId, String identifier, String password);

    PasskeyCredential createPasskeyCredential(
            String usrId, String identifier, byte[] publicKey,
            int signCount, String rpId);

    OidcCredential createOidcCredential(
            String usrId, String identifier,
            String oidcIssuer, String oidcSubject);

    Credential getCredential(String credId);

    List<Credential> listCredentialsForUser(String usrId);

    /** Returns null if no active credential matches. */
    Credential findCredentialByIdentifier(CredentialType type, String identifier);

    PasswordCredential rotatePassword(String credId, String newPassword);
    PasskeyCredential rotatePasskey(
            String credId, byte[] publicKey, int signCount, String rpId);
    OidcCredential rotateOidc(
            String credId, String oidcIssuer, String oidcSubject);

    Credential suspendCredential(String credId);
    Credential reinstateCredential(String credId);
    Credential revokeCredential(String credId);

    /** Throws InvalidCredentialError on either unknown identifier or bad password. */
    VerifiedCredential verifyPassword(String identifier, String password);

    // ─── Sessions ───
    SessionWithToken createSession(String usrId, String credId, long ttlSeconds);

    Session getSession(String sesId);

    Page<Session> listSessionsForUser(String usrId, String cursor, int limit);

    Session verifySessionToken(String token);

    SessionWithToken refreshSession(String sesId);

    Session revokeSession(String sesId);

    // ─── v0.2 MFA store operations (ADR 0008) ───

    TotpEnrollmentResult enrollTotpFactor(String usrId, String identifier);

    WebAuthnEnrollmentResult enrollWebAuthnFactor(
            String usrId, String identifier,
            byte[] publicKey, long signCount, String rpId);

    RecoveryEnrollmentResult enrollRecoveryFactor(String usrId);

    TotpFactor confirmTotpFactor(String mfaId, String code);

    WebAuthnFactor confirmWebAuthnFactor(
            String mfaId,
            byte[] authenticatorData, byte[] clientDataJson, byte[] signature,
            byte[] expectedChallenge, String expectedOrigin);

    java.util.List<Factor> listMfaFactors(String usrId);

    Factor getMfaFactor(String mfaId);

    Factor revokeMfaFactor(String mfaId);

    /**
     * Verify an MFA proof. Throws InvalidCredentialError on mismatch.
     * Does NOT mint a session; the spec's three-step flow is
     * verifyPassword → verifyMfa → createSession.
     */
    MfaVerifyResult verifyMfa(String usrId, MfaProof proof);

    /** Returns null when no policy row exists. */
    UserMfaPolicy getMfaPolicy(String usrId);

    UserMfaPolicy setMfaPolicy(String usrId, boolean required, java.time.Instant graceUntil);

    // ─── v0.3 personal access tokens (ADR 0016) ───

    /**
     * Mint a new personal access token for the user.
     *
     * <p>Returns the persisted record and the plaintext bearer token in
     * {@code pat_<32hex-id>_<base64url-secret>} form. The plaintext
     * token is returned ONCE; the server retains only an Argon2id hash
     * of the secret segment at the cred-password parameter floor.
     * Adopters MUST surface the plaintext to the user immediately and
     * never persist it server-side.
     *
     * <p><b>@security</b> Adopter MUST gate this call so the
     * requesting principal either owns {@code usrId} OR is a
     * sysadmin acting on the user's behalf. The SDK does not
     * enforce. Without route-layer gating, any authenticated user
     * can mint PATs in any other user's name.
     * (security-audit-v0.3.md H7.)
     *
     * @param usrId owner of the new token
     * @param name human-readable label, 1–120 Unicode code units
     * @param scope application-defined scope claims; may be empty
     * @param expiresAt optional expiry; null means no expiry
     */
    CreatePatResult createPat(String usrId, String name, java.util.List<String> scope, java.time.Instant expiresAt);

    /**
     * Read a single PAT row by id.
     *
     * <p><b>@security</b> Adopter MUST gate so the requesting
     * principal either owns the PAT (matches {@code usrId} of the
     * row) OR is a sysadmin. The SDK returns the row regardless —
     * without gating, an unauthenticated / wrong-principal request
     * leaks the PAT's existence, scope, and metadata.
     * (security-audit-v0.3.md H7.)
     */
    PersonalAccessToken getPat(String patId);

    /**
     * Cursor-paginated PAT list for a user. Mirrors listMembers shape.
     *
     * <p><b>@security</b> Adopter MUST gate so the requesting
     * principal either is {@code usrId} OR is a sysadmin. Without
     * gating, any caller can enumerate any user's PATs.
     * (security-audit-v0.3.md H7.)
     *
     * @param status filter by derived status; null returns all
     */
    Page<PersonalAccessToken> listPatsForUser(String usrId, String cursor, int limit, PatStatus status);

    /**
     * Idempotent: revoking an already-revoked PAT returns the existing row.
     *
     * <p><b>@security</b> Adopter MUST gate so the requesting
     * principal either owns the PAT OR is a sysadmin. Without
     * gating, any caller can revoke any user's PAT — locking the
     * legitimate owner out of their own automation.
     * (security-audit-v0.3.md H7.)
     */
    PersonalAccessToken revokePat(String patId);

    /**
     * Verify a PAT bearer per ADR 0016 §"Verification semantics".
     *
     * <p>Throws {@link InvalidPatTokenError} for malformed tokens,
     * missing rows, or wrong-secret matches (the missing/wrong cases
     * MUST conflate). Throws {@link PatRevokedError} for terminal-
     * revoked tokens. Throws {@link PatExpiredError} for past-expiry
     * tokens.
     *
     * <p>On success, side-effect: updates lastUsedAt. Implementations
     * MAY coalesce these writes within a configurable window
     * (60s default) to avoid a write-per-request hot path.
     */
    VerifiedPat verifyPatToken(String token);
}
