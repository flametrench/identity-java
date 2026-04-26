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

    // ─── Users ───
    User createUser();
    User getUser(String usrId);
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
}
