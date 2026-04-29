// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import dev.flametrench.ids.Id;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;

import javax.sql.DataSource;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnabledIfEnvironmentVariable(named = "IDENTITY_POSTGRES_URL", matches = ".+")
class PostgresIdentityStoreTest {

    private static DataSource dataSource;
    private static String schemaSql;

    private PostgresIdentityStore store;

    @BeforeAll
    static void setupClass() throws IOException {
        String url = System.getenv("IDENTITY_POSTGRES_URL");
        URI uri = URI.create(url.replaceFirst("^postgresql:", "http:"));
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setServerNames(new String[] { uri.getHost() });
        ds.setPortNumbers(new int[] { uri.getPort() == -1 ? 5432 : uri.getPort() });
        String path = uri.getPath();
        ds.setDatabaseName(path != null && path.length() > 1 ? path.substring(1) : "postgres");
        if (uri.getUserInfo() != null) {
            String[] parts = uri.getUserInfo().split(":", 2);
            ds.setUser(parts[0]);
            if (parts.length > 1) ds.setPassword(parts[1]);
        }
        dataSource = ds;
        schemaSql = Files.readString(Path.of("src/test/resources/postgres-schema.sql"));
    }

    @BeforeEach
    void resetSchema() throws Exception {
        try (Connection conn = dataSource.getConnection();
             Statement st = conn.createStatement()) {
            st.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;");
            st.execute(schemaSql);
        }
        store = new PostgresIdentityStore(dataSource);
    }

    @Test
    void createUser_isActive() {
        User u = store.createUser();
        assertTrue(u.id().matches("^usr_[0-9a-f]{32}$"));
        assertEquals(Status.ACTIVE, u.status());
    }

    @Test
    void getUser_unknownRaises() {
        assertThrows(NotFoundError.class, () -> store.getUser(Id.generate("usr")));
    }

    @Test
    void suspendReinstateRoundTrip() {
        User u = store.createUser();
        assertEquals(Status.SUSPENDED, store.suspendUser(u.id()).status());
        assertEquals(Status.ACTIVE, store.reinstateUser(u.id()).status());
    }

    @Test
    void revokeUser_cascadesToCredsAndSessions() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(u.id(), "alice@example.com", "pw");
        SessionWithToken sw = store.createSession(u.id(), cred.id(), 3600);
        store.revokeUser(u.id());
        assertEquals(Status.REVOKED, store.getUser(u.id()).status());
        assertEquals(Status.REVOKED, store.getCredential(cred.id()).status());
        assertNotNull(store.getSession(sw.session().id()).revokedAt());
    }

    @Test
    void doubleRevoke_rejected() {
        User u = store.createUser();
        store.revokeUser(u.id());
        assertThrows(AlreadyTerminalError.class, () -> store.revokeUser(u.id()));
    }

    // ─── listUsers (ADR 0015) ───

    @Test
    void listUsers_idOrdered() {
        User a = store.createUser();
        User b = store.createUser();
        User c = store.createUser();
        Page<User> page = store.listUsers(null, 50, null, null);
        assertEquals(java.util.List.of(a.id(), b.id(), c.id()),
                page.data().stream().map(User::id).toList());
        assertNull(page.nextCursor());
    }

    @Test
    void listUsers_statusFilter() {
        User active = store.createUser();
        User suspended = store.createUser();
        store.suspendUser(suspended.id());
        Page<User> page = store.listUsers(null, 50, null, Status.ACTIVE);
        assertEquals(java.util.List.of(active.id()),
                page.data().stream().map(User::id).toList());
    }

    @Test
    void listUsers_queryCaseInsensitive() {
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
    void listUsers_querySkipsRevokedCredentials() {
        User alice = store.createUser();
        Credential cred = store.createPasswordCredential(alice.id(), "gone@example.com", "long-enough-password");
        store.revokeCredential(cred.id());
        Page<User> page = store.listUsers(null, 50, "gone@example.com", null);
        assertTrue(page.data().isEmpty());
    }

    @Test
    void listUsers_cursorWalksPages() {
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
    void listUsers_returnsDisplayName() {
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
    void createUser_storesDisplayName() {
        User u = store.createUser("Alice");
        assertEquals("Alice", u.displayName());
        assertEquals("Alice", store.getUser(u.id()).displayName());
    }

    @Test
    void createUser_defaultsDisplayNameToNull() {
        User u = store.createUser();
        assertNull(u.displayName());
    }

    @Test
    void updateUser_setNoOpClear() {
        User u = store.createUser("Original");
        User renamed = store.updateUser(u.id(), "Renamed");
        assertEquals("Renamed", renamed.displayName());
        User unchanged = store.updateUser(u.id(), IdentityStore.UNSET);
        assertEquals("Renamed", unchanged.displayName());
        User cleared = store.updateUser(u.id(), null);
        assertNull(cleared.displayName());
    }

    @Test
    void updateUser_allowsRenamingSuspended() {
        User u = store.createUser("Before");
        store.suspendUser(u.id());
        User renamed = store.updateUser(u.id(), "After");
        assertEquals("After", renamed.displayName());
        assertEquals(Status.SUSPENDED, renamed.status());
    }

    @Test
    void updateUser_revokedRejected() {
        User u = store.createUser();
        store.revokeUser(u.id());
        assertThrows(AlreadyTerminalError.class,
                () -> store.updateUser(u.id(), "Whatever"));
    }

    @Test
    void updateUser_unknownRejected() {
        assertThrows(NotFoundError.class,
                () -> store.updateUser(dev.flametrench.ids.Id.generate("usr"), "ghost"));
    }

    @Test
    void displayName_unicodeRoundTrip() {
        User u = store.createUser("山田 太郎");
        assertEquals("山田 太郎", store.getUser(u.id()).displayName());
    }

    // ─── Outer-transaction nesting (ADR 0013) ───

    @Test
    void createUser_cooperatesWithOuterTransaction() throws java.sql.SQLException {
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(false);
            PostgresIdentityStore nested = new PostgresIdentityStore(conn);
            User u = nested.createUser("Nested");
            conn.commit();
            User fetched = store.getUser(u.id());
            assertEquals("Nested", fetched.displayName());
        }
    }

    @Test
    void outerRollback_undoesInnerCreate() throws java.sql.SQLException {
        String userId;
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(false);
            PostgresIdentityStore nested = new PostgresIdentityStore(conn);
            User u = nested.createUser();
            userId = u.id();
            conn.rollback();
        }
        assertThrows(NotFoundError.class, () -> store.getUser(userId));
    }

    @Test
    void multipleCallsInOuterTransactionCommitOrRollbackTogether() throws java.sql.SQLException {
        String aId, bId;
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(false);
            PostgresIdentityStore nested = new PostgresIdentityStore(conn);
            User a = nested.createUser();
            User b = nested.createUser();
            aId = a.id();
            bId = b.id();
            conn.rollback();
        }
        assertThrows(NotFoundError.class, () -> store.getUser(aId));
        assertThrows(NotFoundError.class, () -> store.getUser(bId));
    }

    @Test
    void passwordCredential_roundTrip() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(
                u.id(), "alice@example.com", "correct horse battery staple"
        );
        VerifiedCredential v = store.verifyPassword("alice@example.com", "correct horse battery staple");
        assertEquals(u.id(), v.usrId());
        assertEquals(cred.id(), v.credId());
    }

    @Test
    void verifyPassword_wrongRejected() {
        User u = store.createUser();
        store.createPasswordCredential(u.id(), "alice@example.com", "pw");
        assertThrows(InvalidCredentialError.class, () ->
                store.verifyPassword("alice@example.com", "wrong"));
    }

    @Test
    void duplicateActiveCredential_rejected() {
        User u = store.createUser();
        store.createPasswordCredential(u.id(), "alice@example.com", "p1");
        assertThrows(DuplicateCredentialError.class, () ->
                store.createPasswordCredential(u.id(), "alice@example.com", "p2"));
    }

    @Test
    void rotatePassword_revokesOldTerminatesSessions() {
        User u = store.createUser();
        PasswordCredential old = store.createPasswordCredential(u.id(), "alice@example.com", "old");
        SessionWithToken sw = store.createSession(u.id(), old.id(), 3600);
        PasswordCredential next = store.rotatePassword(old.id(), "new");
        assertEquals(old.id(), next.replaces());
        assertEquals(Status.REVOKED, store.getCredential(old.id()).status());
        assertNotNull(store.getSession(sw.session().id()).revokedAt());
        assertThrows(InvalidCredentialError.class, () ->
                store.verifyPassword("alice@example.com", "old"));
        VerifiedCredential ok = store.verifyPassword("alice@example.com", "new");
        assertEquals(next.id(), ok.credId());
    }

    @Test
    void findCredentialByIdentifier_activeOnly() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(u.id(), "alice@example.com", "p");
        Credential found = store.findCredentialByIdentifier(CredentialType.PASSWORD, "alice@example.com");
        assertNotNull(found);
        assertEquals(cred.id(), found.id());
        store.revokeCredential(cred.id());
        assertNull(store.findCredentialByIdentifier(CredentialType.PASSWORD, "alice@example.com"));
    }

    @Test
    void session_tokenRoundTrip() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(u.id(), "alice@example.com", "p");
        SessionWithToken sw = store.createSession(u.id(), cred.id(), 3600);
        assertNotEquals(sw.token(), sw.session().id());
        Session verified = store.verifySessionToken(sw.token());
        assertEquals(sw.session().id(), verified.id());
    }

    @Test
    void verifySessionToken_unknownRejected() {
        assertThrows(InvalidTokenError.class, () -> store.verifySessionToken("nope"));
    }

    @Test
    void verifySessionToken_revokedRejected() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(u.id(), "alice@example.com", "p");
        SessionWithToken sw = store.createSession(u.id(), cred.id(), 3600);
        store.revokeSession(sw.session().id());
        assertThrows(SessionExpiredError.class, () -> store.verifySessionToken(sw.token()));
    }

    @Test
    void refreshSession_returnsNew() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(u.id(), "alice@example.com", "p");
        SessionWithToken sw = store.createSession(u.id(), cred.id(), 3600);
        SessionWithToken refreshed = store.refreshSession(sw.session().id());
        assertNotEquals(sw.session().id(), refreshed.session().id());
        assertNotEquals(sw.token(), refreshed.token());
        assertNotNull(store.getSession(sw.session().id()).revokedAt());
    }

    @Test
    void createSession_shortTtlRejected() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(u.id(), "alice@example.com", "p");
        assertThrows(PreconditionError.class, () ->
                store.createSession(u.id(), cred.id(), 30));
    }

    @Test
    void createSession_suspendedCredRejected() {
        User u = store.createUser();
        PasswordCredential cred = store.createPasswordCredential(u.id(), "alice@example.com", "p");
        store.suspendCredential(cred.id());
        assertThrows(CredentialNotActiveError.class, () ->
                store.createSession(u.id(), cred.id(), 3600));
    }

    @Test
    void totpEnrollConfirmVerifyRoundTrip() {
        User u = store.createUser();
        TotpEnrollmentResult enroll = store.enrollTotpFactor(u.id(), "iPhone");
        assertEquals(FactorStatus.PENDING, enroll.factor().status());
        assertTrue(enroll.secretB32().length() > 0);
        assertTrue(enroll.otpauthUri().startsWith("otpauth://totp/"));
        byte[] secret = base32Decode(enroll.secretB32());
        String code = Totp.compute(secret, Instant.now().getEpochSecond());
        TotpFactor active = store.confirmTotpFactor(enroll.factor().id(), code);
        assertEquals(FactorStatus.ACTIVE, active.status());
        MfaVerifyResult result = store.verifyMfa(u.id(), new TotpProof(code));
        assertEquals(FactorType.TOTP, result.type());
        assertEquals(active.id(), result.mfaId());
    }

    @Test
    void totp_enforcesAtMostOneActive() {
        User u = store.createUser();
        TotpEnrollmentResult first = store.enrollTotpFactor(u.id(), "iPhone");
        String code = Totp.compute(base32Decode(first.secretB32()), Instant.now().getEpochSecond());
        store.confirmTotpFactor(first.factor().id(), code);
        assertThrows(PreconditionError.class, () ->
                store.enrollTotpFactor(u.id(), "Yubico"));
    }

    @Test
    void recoveryCodes_consumeOnce() {
        User u = store.createUser();
        RecoveryEnrollmentResult enroll = store.enrollRecoveryFactor(u.id());
        assertEquals(10, enroll.codes().size());
        String first = enroll.codes().get(0);
        MfaVerifyResult result = store.verifyMfa(u.id(), new RecoveryProof(first));
        assertEquals(FactorType.RECOVERY, result.type());
        assertThrows(InvalidCredentialError.class, () ->
                store.verifyMfa(u.id(), new RecoveryProof(first)));
        List<Factor> factors = store.listMfaFactors(u.id());
        Factor recovery = factors.stream().filter(f -> f.type() == FactorType.RECOVERY)
                .findFirst().orElseThrow();
        assertTrue(recovery instanceof RecoveryFactor);
        assertEquals(9, ((RecoveryFactor) recovery).remaining());
    }

    @Test
    void recoveryFactor_rejectsMalformed() {
        User u = store.createUser();
        store.enrollRecoveryFactor(u.id());
        assertThrows(InvalidCredentialError.class, () ->
                store.verifyMfa(u.id(), new RecoveryProof("not-a-code")));
    }

    @Test
    void revokeMfa_freesSingletonSlot() {
        User u = store.createUser();
        TotpEnrollmentResult first = store.enrollTotpFactor(u.id(), "iPhone");
        String code = Totp.compute(base32Decode(first.secretB32()), Instant.now().getEpochSecond());
        store.confirmTotpFactor(first.factor().id(), code);
        store.revokeMfaFactor(first.factor().id());
        TotpEnrollmentResult second = store.enrollTotpFactor(u.id(), "Yubico");
        assertEquals(FactorStatus.PENDING, second.factor().status());
    }

    @Test
    void setMfaPolicy_upserts() {
        User u = store.createUser();
        assertNull(store.getMfaPolicy(u.id()));
        Instant grace = Instant.now().plus(14, ChronoUnit.DAYS);
        UserMfaPolicy set1 = store.setMfaPolicy(u.id(), true, grace);
        assertTrue(set1.required());
        assertNotNull(set1.graceUntil());
        UserMfaPolicy fetched = store.getMfaPolicy(u.id());
        assertNotNull(fetched);
        assertTrue(fetched.required());
        UserMfaPolicy set2 = store.setMfaPolicy(u.id(), true, null);
        assertNull(set2.graceUntil());
    }

    @Test
    void getMfaPolicy_unknownUserRaises() {
        assertThrows(NotFoundError.class, () -> store.getMfaPolicy(Id.generate("usr")));
    }

    /** RFC 4648 base32 decode (uppercase, ignores padding). */
    private static byte[] base32Decode(String s) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        String stripped = s.toUpperCase().replaceAll("=+$", "");
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int bits = 0;
        int value = 0;
        for (char ch : stripped.toCharArray()) {
            int idx = alphabet.indexOf(ch);
            if (idx < 0) throw new IllegalArgumentException("invalid base32 char " + ch);
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) {
                out.write((value >>> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }
}
