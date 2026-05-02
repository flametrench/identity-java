// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import dev.flametrench.ids.Id;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PatTest {

    /** Mutable wall-clock test fixture (so tests can advance time deterministically). */
    static class TestClock extends Clock {
        private Instant now;

        TestClock(Instant start) {
            this.now = start;
        }

        public void advance(Duration d) {
            this.now = this.now.plus(d);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    // ─── In-memory tests ──────────────────────────────────────────

    @Nested
    class InMemory {
        TestClock clock;
        InMemoryIdentityStore store;

        @BeforeEach
        void setup() {
            clock = new TestClock(Instant.parse("2026-05-01T12:00:00Z"));
            // coalesce=0 for deterministic last_used_at assertions; the
            // coalescing tests construct their own with a 60s window.
            store = new InMemoryIdentityStore(clock, 0L);
        }

        @Test
        void createPat_returnsRecordAndToken() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(u.id(), "laptop-cli", List.of("repo:read"), null);
            assertTrue(r.pat().id().matches("^pat_[0-9a-f]{32}$"));
            assertEquals("laptop-cli", r.pat().name());
            assertEquals(List.of("repo:read"), r.pat().scope());
            assertEquals(PatStatus.ACTIVE, r.pat().status());
            assertNull(r.pat().lastUsedAt());
            assertNull(r.pat().expiresAt());
            assertTrue(r.token().matches("^pat_[0-9a-f]{32}_[A-Za-z0-9_-]+$"));
            // The id segment in the token must match the row's id.
            assertEquals(r.pat().id().substring(4), r.token().substring(4, 36));
        }

        @Test
        void createPat_rejectsEmptyName() {
            User u = store.createUser();
            assertThrows(PreconditionError.class,
                    () -> store.createPat(u.id(), "", List.of(), null));
        }

        @Test
        void createPat_rejectsLongName() {
            User u = store.createUser();
            assertThrows(PreconditionError.class,
                    () -> store.createPat(u.id(), "x".repeat(121), List.of(), null));
        }

        @Test
        void createPat_rejectsPastExpiry() {
            User u = store.createUser();
            assertThrows(PreconditionError.class,
                    () -> store.createPat(u.id(), "cli", List.of(), Instant.parse("2026-04-01T00:00:00Z")));
        }

        // security-audit-v0.3.md H1: ADR 0016 §"Constraints" caps expires_at
        // at 365 days from creation. Pre-fix this was unenforced.
        @Test
        void createPat_acceptsExpiryAtCap() {
            User u = store.createUser();
            Instant exp = clock.instant().plusSeconds(365L * 86400L);
            CreatePatResult r = store.createPat(u.id(), "cli", List.of(), exp);
            assertEquals(exp, r.pat().expiresAt());
        }

        @Test
        void createPat_rejectsExpiryBeyondCap() {
            User u = store.createUser();
            Instant exp = clock.instant().plusSeconds(365L * 86400L + 1L);
            assertThrows(PreconditionError.class,
                    () -> store.createPat(u.id(), "cli", List.of(), exp));
        }

        @Test
        void createPat_refusesRevokedUser() {
            User u = store.createUser();
            store.revokeUser(u.id());
            assertThrows(AlreadyTerminalError.class,
                    () -> store.createPat(u.id(), "cli", List.of(), null));
        }

        @Test
        void verifyPatToken_happyPath() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(u.id(), "cli", List.of("admin"), null);
            VerifiedPat v = store.verifyPatToken(r.token());
            assertEquals(r.pat().id(), v.patId());
            assertEquals(u.id(), v.usrId());
            assertEquals(List.of("admin"), v.scope());
        }

        @Test
        void verifyPatToken_updatesLastUsedAtWhenCoalesceZero() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(u.id(), "cli", List.of(), null);
            assertNull(r.pat().lastUsedAt());
            clock.advance(Duration.ofSeconds(5));
            store.verifyPatToken(r.token());
            assertEquals(clock.instant(), store.getPat(r.pat().id()).lastUsedAt());
        }

        @Test
        void verifyPatToken_throwsInvalidForMalformed() {
            assertThrows(InvalidPatTokenError.class, () -> store.verifyPatToken("not-a-pat"));
        }

        @Test
        void verifyPatToken_throwsInvalidForNonPatPrefix() {
            assertThrows(InvalidPatTokenError.class,
                    () -> store.verifyPatToken("shr_" + "a".repeat(32) + "_secret"));
        }

        @Test
        void verifyPatToken_throwsInvalidForMissingRow_timingOracleDefense() {
            assertThrows(InvalidPatTokenError.class,
                    () -> store.verifyPatToken("pat_" + "a".repeat(32) + "_anysecret"));
        }

        @Test
        void verifyPatToken_throwsInvalidForWrongSecret() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(u.id(), "cli", List.of(), null);
            String idHex = r.pat().id().substring(4);
            assertThrows(InvalidPatTokenError.class,
                    () -> store.verifyPatToken("pat_" + idHex + "_wrongSecret"));
        }

        @Test
        void verifyPatToken_throwsRevokedBeforeExpiryCheck() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(
                    u.id(), "cli", List.of(), Instant.parse("2026-06-01T00:00:00Z"));
            store.revokePat(r.pat().id());
            assertThrows(PatRevokedError.class, () -> store.verifyPatToken(r.token()));
        }

        @Test
        void verifyPatToken_throwsExpired() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(
                    u.id(), "cli", List.of(), Instant.parse("2026-05-01T13:00:00Z"));
            clock.advance(Duration.ofDays(1));
            assertThrows(PatExpiredError.class, () -> store.verifyPatToken(r.token()));
        }

        @Test
        void revokePat_marksStatusRevoked() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(u.id(), "cli", List.of(), null);
            PersonalAccessToken revoked = store.revokePat(r.pat().id());
            assertEquals(PatStatus.REVOKED, revoked.status());
            assertEquals(clock.instant(), revoked.revokedAt());
        }

        @Test
        void revokePat_isIdempotent() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(u.id(), "cli", List.of(), null);
            PersonalAccessToken first = store.revokePat(r.pat().id());
            clock.advance(Duration.ofHours(1));
            PersonalAccessToken second = store.revokePat(r.pat().id());
            assertEquals(first.revokedAt(), second.revokedAt());
        }

        @Test
        void revokePat_unknownRaisesNotFound() {
            assertThrows(NotFoundError.class, () -> store.revokePat(Id.generate("pat")));
        }

        @Test
        void listPatsForUser_returnsIdOrdered() throws InterruptedException {
            User alice = store.createUser();
            User bob = store.createUser();
            CreatePatResult a1 = store.createPat(alice.id(), "a-1", List.of(), null);
            Thread.sleep(2);
            CreatePatResult a2 = store.createPat(alice.id(), "a-2", List.of(), null);
            store.createPat(bob.id(), "bob-1", List.of(), null);

            Page<PersonalAccessToken> page = store.listPatsForUser(alice.id(), null, 50, null);
            assertEquals(2, page.data().size());
            assertEquals(a1.pat().id(), page.data().get(0).id());
            assertEquals(a2.pat().id(), page.data().get(1).id());
        }

        @Test
        void listPatsForUser_filtersByStatus() {
            User u = store.createUser();
            CreatePatResult live = store.createPat(u.id(), "live", List.of(), null);
            CreatePatResult rev = store.createPat(u.id(), "rev", List.of(), null);
            store.revokePat(rev.pat().id());

            Page<PersonalAccessToken> active = store.listPatsForUser(u.id(), null, 50, PatStatus.ACTIVE);
            assertEquals(1, active.data().size());
            assertEquals(live.pat().id(), active.data().get(0).id());

            Page<PersonalAccessToken> revoked = store.listPatsForUser(u.id(), null, 50, PatStatus.REVOKED);
            assertEquals(1, revoked.data().size());
            assertEquals(rev.pat().id(), revoked.data().get(0).id());
        }

        @Test
        void lastUsedAt_coalescesWithinWindow() {
            TestClock c = new TestClock(Instant.parse("2026-05-01T12:00:00Z"));
            InMemoryIdentityStore s = new InMemoryIdentityStore(c, 60L);
            User u = s.createUser();
            CreatePatResult r = s.createPat(u.id(), "cli", List.of(), null);

            c.advance(Duration.ofSeconds(5));
            s.verifyPatToken(r.token());
            Instant after1 = s.getPat(r.pat().id()).lastUsedAt();

            c.advance(Duration.ofSeconds(10));
            s.verifyPatToken(r.token());
            Instant after2 = s.getPat(r.pat().id()).lastUsedAt();
            assertEquals(after1, after2);
        }

        @Test
        void lastUsedAt_updatesAfterWindow() {
            TestClock c = new TestClock(Instant.parse("2026-05-01T12:00:00Z"));
            InMemoryIdentityStore s = new InMemoryIdentityStore(c, 60L);
            User u = s.createUser();
            CreatePatResult r = s.createPat(u.id(), "cli", List.of(), null);

            c.advance(Duration.ofSeconds(5));
            s.verifyPatToken(r.token());
            Instant after1 = s.getPat(r.pat().id()).lastUsedAt();

            c.advance(Duration.ofSeconds(90)); // 95s past first verify
            s.verifyPatToken(r.token());
            Instant after2 = s.getPat(r.pat().id()).lastUsedAt();
            assertNotEquals(after1, after2);
            assertEquals(c.instant(), after2);
        }
    }

    // ─── Postgres tests (gated) ──────────────────────────────────

    @Nested
    @EnabledIfEnvironmentVariable(named = "IDENTITY_POSTGRES_URL", matches = ".+")
    class Pg {
        DataSource dataSource;
        String schemaSql;
        TestClock clock;
        PostgresIdentityStore store;

        @BeforeEach
        void setupAndReset() throws Exception {
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
            try (Connection conn = dataSource.getConnection();
                 Statement st = conn.createStatement()) {
                st.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;");
                st.execute(schemaSql);
            }
            clock = new TestClock(Instant.parse("2026-05-01T12:00:00Z"));
            store = new PostgresIdentityStore(dataSource, clock, 0L);
        }

        @Test
        void createPat_persistsRow() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(u.id(), "laptop-cli", List.of("repo:read"), null);
            assertTrue(r.pat().id().matches("^pat_[0-9a-f]{32}$"));
            assertEquals(List.of("repo:read"), r.pat().scope());
            assertEquals(PatStatus.ACTIVE, r.pat().status());
            assertTrue(r.token().matches("^pat_[0-9a-f]{32}_[A-Za-z0-9_-]+$"));
        }

        @Test
        void createPat_rejectsRevokedUser() {
            User u = store.createUser();
            store.revokeUser(u.id());
            assertThrows(AlreadyTerminalError.class,
                    () -> store.createPat(u.id(), "cli", List.of(), null));
        }

        @Test
        void verifyPatToken_returnsVerified() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(u.id(), "cli", List.of("admin"), null);
            VerifiedPat v = store.verifyPatToken(r.token());
            assertEquals(r.pat().id(), v.patId());
            assertEquals(u.id(), v.usrId());
            assertEquals(List.of("admin"), v.scope());
        }

        @Test
        void verifyPatToken_invalidForMissingRow() {
            assertThrows(InvalidPatTokenError.class,
                    () -> store.verifyPatToken("pat_" + "a".repeat(32) + "_anysecret"));
        }

        @Test
        void verifyPatToken_invalidForWrongSecret() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(u.id(), "cli", List.of(), null);
            String idHex = r.pat().id().substring(4);
            assertThrows(InvalidPatTokenError.class,
                    () -> store.verifyPatToken("pat_" + idHex + "_wrongSecret"));
        }

        @Test
        void verifyPatToken_revokedBeforeExpiry() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(
                    u.id(), "cli", List.of(), Instant.parse("2026-06-01T00:00:00Z"));
            store.revokePat(r.pat().id());
            assertThrows(PatRevokedError.class, () -> store.verifyPatToken(r.token()));
        }

        @Test
        void verifyPatToken_expiredAfterExpiresAt() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(
                    u.id(), "cli", List.of(), Instant.parse("2026-05-01T13:00:00Z"));
            clock.advance(Duration.ofDays(1));
            assertThrows(PatExpiredError.class, () -> store.verifyPatToken(r.token()));
        }

        @Test
        void revokePat_idempotent() {
            User u = store.createUser();
            CreatePatResult r = store.createPat(u.id(), "cli", List.of(), null);
            PersonalAccessToken first = store.revokePat(r.pat().id());
            clock.advance(Duration.ofHours(1));
            PersonalAccessToken second = store.revokePat(r.pat().id());
            assertEquals(first.revokedAt(), second.revokedAt());
        }

        @Test
        void revokePat_unknownNotFound() {
            assertThrows(NotFoundError.class, () -> store.revokePat(Id.generate("pat")));
        }

        @Test
        void listPats_filtersByStatus() {
            User u = store.createUser();
            CreatePatResult live = store.createPat(u.id(), "live", List.of(), null);
            CreatePatResult rev = store.createPat(u.id(), "rev", List.of(), null);
            store.revokePat(rev.pat().id());
            Page<PersonalAccessToken> active = store.listPatsForUser(u.id(), null, 50, PatStatus.ACTIVE);
            assertEquals(1, active.data().size());
            assertEquals(live.pat().id(), active.data().get(0).id());
        }

        @Test
        void coalescesLastUsedAtWithinWindow() {
            TestClock c = new TestClock(Instant.parse("2026-05-01T12:00:00Z"));
            PostgresIdentityStore s = new PostgresIdentityStore(dataSource, c, 60L);
            User u = s.createUser();
            CreatePatResult r = s.createPat(u.id(), "cli", List.of(), null);

            c.advance(Duration.ofSeconds(5));
            s.verifyPatToken(r.token());
            Instant after1 = s.getPat(r.pat().id()).lastUsedAt();

            c.advance(Duration.ofSeconds(10));
            s.verifyPatToken(r.token());
            Instant after2 = s.getPat(r.pat().id()).lastUsedAt();
            assertEquals(after1, after2);

            c.advance(Duration.ofSeconds(90));
            s.verifyPatToken(r.token());
            Instant after3 = s.getPat(r.pat().id()).lastUsedAt();
            assertNotEquals(after1, after3);
        }

        @Test
        void cooperatesWithCallerOwnedConnectionViaSavepoint() throws Exception {
            try (Connection conn = dataSource.getConnection()) {
                conn.setAutoCommit(false);
                PostgresIdentityStore txStore = new PostgresIdentityStore(conn, clock, 0L);
                User u = txStore.createUser();
                CreatePatResult r = txStore.createPat(u.id(), "cli", List.of(), null);
                txStore.revokePat(r.pat().id());
                conn.commit();

                PersonalAccessToken reread = store.getPat(r.pat().id());
                assertEquals(PatStatus.REVOKED, reread.status());
            }
        }
    }
}
