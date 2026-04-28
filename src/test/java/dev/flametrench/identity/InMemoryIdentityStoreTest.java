// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryIdentityStoreTest {

    private InMemoryIdentityStore store;

    @BeforeEach
    void setUp() {
        store = new InMemoryIdentityStore();
    }

    // ─── User lifecycle ───

    @Test
    void createReturnsActiveUserWithUsrId() {
        User u = store.createUser();
        assertTrue(u.id().matches("^usr_[0-9a-f]{32}$"));
        assertEquals(Status.ACTIVE, u.status());
    }

    @Test
    void getUnknownUserRaises() {
        assertThrows(NotFoundError.class,
                () -> store.getUser("usr_00000000000000000000000000000001"));
    }

    @Test
    void suspendThenReinstateRoundTrip() {
        User u = store.createUser();
        User s = store.suspendUser(u.id());
        assertEquals(Status.SUSPENDED, s.status());
        User r = store.reinstateUser(u.id());
        assertEquals(Status.ACTIVE, r.status());
    }

    @Test
    void cannotReinstateActiveUser() {
        User u = store.createUser();
        assertThrows(PreconditionError.class, () -> store.reinstateUser(u.id()));
    }

    @Test
    void revokeIsTerminal() {
        User u = store.createUser();
        store.revokeUser(u.id());
        assertThrows(AlreadyTerminalError.class, () -> store.revokeUser(u.id()));
    }

    // ─── Password credentials ───

    @Test
    void createThenVerifyRoundTrip() {
        User u = store.createUser();
        store.createPasswordCredential(u.id(), "alice@example.com", "correcthorsebatterystaple");
        VerifiedCredential v = store.verifyPassword("alice@example.com", "correcthorsebatterystaple");
        assertEquals(u.id(), v.usrId());
    }

    @Test
    void wrongPasswordRaises() {
        User u = store.createUser();
        store.createPasswordCredential(u.id(), "alice@example.com", "right");
        assertThrows(InvalidCredentialError.class,
                () -> store.verifyPassword("alice@example.com", "wrong"));
    }

    @Test
    void unknownIdentifierRaises() {
        assertThrows(InvalidCredentialError.class,
                () -> store.verifyPassword("nobody@example.com", "anything"));
    }

    @Test
    void duplicateIdentifierRejected() {
        User u1 = store.createUser();
        User u2 = store.createUser();
        store.createPasswordCredential(u1.id(), "shared@example.com", "x");
        assertThrows(DuplicateCredentialError.class,
                () -> store.createPasswordCredential(u2.id(), "shared@example.com", "y"));
    }

    @Test
    void rotationRevokesOldAndReturnsNew() {
        User u = store.createUser();
        PasswordCredential old = store.createPasswordCredential(
                u.id(), "alice@example.com", "v1");
        PasswordCredential fresh = store.rotatePassword(old.id(), "v2");
        assertEquals(old.id(), fresh.replaces());
        assertThrows(InvalidCredentialError.class,
                () -> store.verifyPassword("alice@example.com", "v1"));
        VerifiedCredential v = store.verifyPassword("alice@example.com", "v2");
        assertEquals(fresh.id(), v.credId());
    }

    @Test
    void revokeUserCascadesCredentials() {
        User u = store.createUser();
        store.createPasswordCredential(u.id(), "alice@example.com", "v1");
        store.revokeUser(u.id());
        assertThrows(InvalidCredentialError.class,
                () -> store.verifyPassword("alice@example.com", "v1"));
    }

    // ─── ADR 0008: usr_mfa_policy gate on verifyPassword ───

    @Test
    void verifyPassword_mfaRequiredFalseWhenNoPolicy() {
        User u = store.createUser();
        store.createPasswordCredential(u.id(), "a@x", "pw");
        VerifiedCredential v = store.verifyPassword("a@x", "pw");
        org.junit.jupiter.api.Assertions.assertFalse(v.mfaRequired());
    }

    @Test
    void verifyPassword_mfaRequiredTrueWhenPolicyActiveAndNoGrace() {
        User u = store.createUser();
        store.createPasswordCredential(u.id(), "a@x", "pw");
        store.setMfaPolicy(u.id(), true, null);
        VerifiedCredential v = store.verifyPassword("a@x", "pw");
        org.junit.jupiter.api.Assertions.assertTrue(v.mfaRequired());
    }

    @Test
    void verifyPassword_mfaRequiredFalseDuringGraceWindow() {
        User u = store.createUser();
        store.createPasswordCredential(u.id(), "a@x", "pw");
        java.time.Instant future = java.time.Instant.now().plus(java.time.Duration.ofDays(7));
        store.setMfaPolicy(u.id(), true, future);
        VerifiedCredential v = store.verifyPassword("a@x", "pw");
        org.junit.jupiter.api.Assertions.assertFalse(v.mfaRequired());
    }

    @Test
    void verifyPassword_mfaRequiredFalseWhenRequiredFalse() {
        User u = store.createUser();
        store.createPasswordCredential(u.id(), "a@x", "pw");
        store.setMfaPolicy(u.id(), false, null);
        VerifiedCredential v = store.verifyPassword("a@x", "pw");
        org.junit.jupiter.api.Assertions.assertFalse(v.mfaRequired());
    }

    // ─── Sessions ───

    @Test
    void createThenVerifyToken() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(
                u.id(), "alice@example.com", "pw");
        SessionWithToken sw = store.createSession(u.id(), cred.id(), 3600);
        Session session = store.verifySessionToken(sw.token());
        assertEquals(sw.session().id(), session.id());
        assertEquals(u.id(), session.usrId());
    }

    @Test
    void rejectUnknownToken() {
        assertThrows(InvalidTokenError.class,
                () -> store.verifySessionToken("definitely-not-a-real-token"));
    }

    @Test
    void refreshRevokesOldIssuesNew() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(
                u.id(), "alice@example.com", "pw");
        SessionWithToken sw1 = store.createSession(u.id(), cred.id(), 3600);
        SessionWithToken sw2 = store.refreshSession(sw1.session().id());
        assertNotEquals(sw1.session().id(), sw2.session().id());
        assertThrows(InvalidTokenError.class,
                () -> store.verifySessionToken(sw1.token()));
        store.verifySessionToken(sw2.token());
    }

    @Test
    void rotationTerminatesSessionsBoundToOldCred() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(
                u.id(), "alice@example.com", "v1");
        SessionWithToken sw = store.createSession(u.id(), cred.id(), 3600);
        store.rotatePassword(cred.id(), "v2");
        assertThrows(InvalidTokenError.class,
                () -> store.verifySessionToken(sw.token()));
    }

    @Test
    void rejectsTtlBelow60() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(
                u.id(), "alice@example.com", "pw");
        assertThrows(PreconditionError.class,
                () -> store.createSession(u.id(), cred.id(), 30));
    }

    @Test
    void revokeSessionInvalidatesToken() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(
                u.id(), "alice@example.com", "pw");
        SessionWithToken sw = store.createSession(u.id(), cred.id(), 3600);
        store.revokeSession(sw.session().id());
        assertThrows(RuntimeException.class,
                () -> store.verifySessionToken(sw.token()));
    }

    @Test
    void suspendingCredentialTerminatesSessions() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(
                u.id(), "alice@example.com", "pw");
        SessionWithToken sw = store.createSession(u.id(), cred.id(), 3600);
        store.suspendCredential(cred.id());
        assertThrows(InvalidTokenError.class,
                () -> store.verifySessionToken(sw.token()));
    }
}
