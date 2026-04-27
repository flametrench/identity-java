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
