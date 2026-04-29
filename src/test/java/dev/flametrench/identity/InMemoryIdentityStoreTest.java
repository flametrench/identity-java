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

    // ─── listUsers (ADR 0015) ───

    @Test
    void listUsersReturnsAllInIdAscOrder() {
        User a = store.createUser();
        User b = store.createUser();
        User c = store.createUser();
        Page<User> page = store.listUsers(null, 50, null, null);
        assertEquals(java.util.List.of(a.id(), b.id(), c.id()),
                page.data().stream().map(User::id).toList());
        assertNull(page.nextCursor());
    }

    @Test
    void listUsersStatusFilterExcludesOthers() {
        User active = store.createUser();
        User suspended = store.createUser();
        store.suspendUser(suspended.id());
        Page<User> page = store.listUsers(null, 50, null, Status.ACTIVE);
        assertEquals(java.util.List.of(active.id()),
                page.data().stream().map(User::id).toList());
    }

    @Test
    void listUsersQueryCaseInsensitiveSubstring() {
        User alice = store.createUser();
        store.createPasswordCredential(alice.id(), "alice@example.com", "long-enough-password");
        User bob = store.createUser();
        store.createPasswordCredential(bob.id(), "bob@example.com", "long-enough-password");
        User carol = store.createUser();
        store.createPasswordCredential(carol.id(), "carol@other.test", "long-enough-password");
        Page<User> page = store.listUsers(null, 50, "EXAMPLE", null);
        assertEquals(java.util.Set.of(alice.id(), bob.id()),
                page.data().stream().map(User::id).collect(java.util.stream.Collectors.toSet()));
    }

    @Test
    void listUsersCursorWalksPages() {
        java.util.List<String> ids = new java.util.ArrayList<>();
        for (int i = 0; i < 5; i++) ids.add(store.createUser().id());
        Page<User> page1 = store.listUsers(null, 2, null, null);
        assertEquals(java.util.List.of(ids.get(0), ids.get(1)),
                page1.data().stream().map(User::id).toList());
        Page<User> page2 = store.listUsers(page1.nextCursor(), 2, null, null);
        assertEquals(java.util.List.of(ids.get(2), ids.get(3)),
                page2.data().stream().map(User::id).toList());
        Page<User> page3 = store.listUsers(page2.nextCursor(), 2, null, null);
        assertEquals(java.util.List.of(ids.get(4)),
                page3.data().stream().map(User::id).toList());
        assertNull(page3.nextCursor());
    }

    @Test
    void listUsersReturnsDisplayName() {
        User alice = store.createUser("Alice");
        User bob = store.createUser();
        Page<User> page = store.listUsers(null, 50, null, null);
        java.util.Map<String, String> byId = new java.util.HashMap<>();
        for (User u : page.data()) byId.put(u.id(), u.displayName());
        assertEquals("Alice", byId.get(alice.id()));
        assertNull(byId.get(bob.id()));
    }

    // ─── display_name (ADR 0014) ───

    @Test
    void createUserStoresDisplayName() {
        User u = store.createUser("Alice");
        assertEquals("Alice", u.displayName());
        assertEquals("Alice", store.getUser(u.id()).displayName());
    }

    @Test
    void createUserDefaultsDisplayNameToNull() {
        User u = store.createUser();
        assertNull(u.displayName());
    }

    @Test
    void updateUserSetNoOpClear() {
        User u = store.createUser("Original");
        User renamed = store.updateUser(u.id(), "Renamed");
        assertEquals("Renamed", renamed.displayName());
        // UNSET means "no change".
        User unchanged = store.updateUser(u.id(), IdentityStore.UNSET);
        assertEquals("Renamed", unchanged.displayName());
        // null means "clear".
        User cleared = store.updateUser(u.id(), null);
        assertNull(cleared.displayName());
    }

    @Test
    void updateUserAllowsRenamingSuspended() {
        User u = store.createUser("Before");
        store.suspendUser(u.id());
        User renamed = store.updateUser(u.id(), "After");
        assertEquals("After", renamed.displayName());
        assertEquals(Status.SUSPENDED, renamed.status());
    }

    @Test
    void updateUserRevokedRejected() {
        User u = store.createUser();
        store.revokeUser(u.id());
        assertThrows(AlreadyTerminalError.class,
                () -> store.updateUser(u.id(), "Whatever"));
    }

    @Test
    void displayNameUnicodeRoundTrip() {
        User u = store.createUser("山田 太郎");
        assertEquals("山田 太郎", store.getUser(u.id()).displayName());
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
