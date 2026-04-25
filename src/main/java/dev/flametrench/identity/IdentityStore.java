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
}
