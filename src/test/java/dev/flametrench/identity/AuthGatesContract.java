// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Store-agnostic tests for TOTP replay protection, user-status gates and
 * recovery re-enrollment (ADR 0008, ADR 0016, docs/identity.md §Lifecycle).
 * Each refusal also asserts that the refused call changed nothing.
 * Subclassed once per store.
 */
abstract class AuthGatesContract {

    private static final String PASSWORD = "long-enough-password-for-floor";

    protected abstract IdentityStore newStore(Clock clock);

    protected IdentityStore store;
    private final AtomicReference<Instant> now = new AtomicReference<>();

    @BeforeEach
    void setUpStore() {
        now.set(Instant.parse("2026-01-01T00:00:00Z"));
        store = newStore(new Clock() {
            @Override public Instant instant() { return now.get(); }
            @Override public ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(ZoneId z) { return this; }
        });
    }

    private void setClock(String iso) {
        now.set(Instant.parse(iso));
    }

    private static byte[] decodeBase32(String s) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int bits = 0, value = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (char c : s.replaceAll("=+$", "").toCharArray()) {
            value = (value << 5) | alphabet.indexOf(c);
            bits += 5;
            if (bits >= 8) {
                out.write((value >>> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }

    // ─── TOTP replay (design 3A) ───

    private record Enrolled(String usrId, String mfaId, byte[] secret) {}

    /** Enroll and confirm a TOTP factor at 00:00:00, then move the clock to 00:01:00. */
    private Enrolled enrolledTotp() {
        String usrId = store.createUser().id();
        TotpEnrollmentResult r = store.enrollTotpFactor(usrId, "totp@example.com");
        byte[] secret = decodeBase32(r.secretB32());
        store.confirmTotpFactor(r.factor().id(), code(secret));
        setClock("2026-01-01T00:01:00Z");
        return new Enrolled(usrId, r.factor().id(), secret);
    }

    private String code(byte[] secret) {
        return Totp.compute(secret, now.get().getEpochSecond());
    }

    @Test
    void totp_sameCodeTwice_secondIsReplayed_andFactorStillUsable() {
        Enrolled e = enrolledTotp();
        String c = code(e.secret());
        store.verifyMfa(e.usrId(), new TotpProof(c));
        ReplayedTotpError err = assertThrows(ReplayedTotpError.class,
                () -> store.verifyMfa(e.usrId(), new TotpProof(c)));
        assertEquals("unauthorized.totp_replayed", err.getCode());
        assertInstanceOf(InvalidCredentialError.class, err);

        // The refusal changed nothing: the next step's code is accepted.
        setClock("2026-01-01T00:01:30Z");
        assertEquals(e.mfaId(), store.verifyMfa(e.usrId(), new TotpProof(code(e.secret()))).mfaId());
    }

    @Test
    void totp_neverUsedOlderStep_rejectedAfterNewerAccepted() {
        Enrolled e = enrolledTotp();
        String older = code(e.secret());
        setClock("2026-01-01T00:01:30Z");
        store.verifyMfa(e.usrId(), new TotpProof(code(e.secret())));
        // `older` is inside the ±1 drift window but its step <= last accepted.
        assertThrows(ReplayedTotpError.class, () -> store.verifyMfa(e.usrId(), new TotpProof(older)));
    }

    @Test
    void totp_confirmCodeCannotBeReplayedIntoVerify() {
        String usrId = store.createUser().id();
        TotpEnrollmentResult r = store.enrollTotpFactor(usrId, "totp@example.com");
        byte[] secret = decodeBase32(r.secretB32());
        String c = code(secret);
        store.confirmTotpFactor(r.factor().id(), c);
        assertThrows(ReplayedTotpError.class, () -> store.verifyMfa(usrId, new TotpProof(c)));
    }

    @Test
    void totp_wrongCode_isInvalidNotReplayed_andDoesNotAdvanceStep() {
        Enrolled e = enrolledTotp();
        String good = code(e.secret());
        String bad = good.equals("000000") ? "111111" : "000000";
        InvalidCredentialError err = assertThrows(InvalidCredentialError.class,
                () -> store.verifyMfa(e.usrId(), new TotpProof(bad)));
        assertFalse(err instanceof ReplayedTotpError);
        store.verifyMfa(e.usrId(), new TotpProof(good));
    }

    @Test
    void totp_concurrentVerifiesOfOneCode_exactlyOneSucceeds() throws Exception {
        Enrolled e = enrolledTotp();
        String c = code(e.secret());
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                Callable<Boolean> attempt = () -> {
                    start.await();
                    try {
                        store.verifyMfa(e.usrId(), new TotpProof(c));
                        return true;
                    } catch (ReplayedTotpError replayed) {
                        return false;
                    }
                };
                results.add(pool.submit(attempt));
            }
            start.countDown();
            int accepted = 0;
            for (Future<Boolean> f : results) if (f.get()) accepted++;
            assertEquals(1, accepted);
        } finally {
            pool.shutdownNow();
        }
    }

    // ─── verifyPassword ───

    @Test
    void verifyPassword_suspendedUser_refusedWithSameErrorAsWrongPassword() {
        String usrId = store.createUser().id();
        store.createPasswordCredential(usrId, "sus@example.com", PASSWORD);
        InvalidCredentialError wrongPassword = assertThrows(InvalidCredentialError.class,
                () -> store.verifyPassword("sus@example.com", "not-the-password-at-all"));
        store.suspendUser(usrId);

        InvalidCredentialError suspended = assertThrows(InvalidCredentialError.class,
                () -> store.verifyPassword("sus@example.com", PASSWORD));
        assertEquals(wrongPassword.getMessage(), suspended.getMessage());
        assertEquals(wrongPassword.getCode(), suspended.getCode());

        // The refusal changed nothing: after reinstate the password verifies.
        store.reinstateUser(usrId);
        assertEquals(usrId, store.verifyPassword("sus@example.com", PASSWORD).usrId());
    }

    // ─── PATs ───

    private CreatePatResult pat(String usrId) {
        return store.createPat(new CreatePatInput(usrId, "ci", List.of(), null));
    }

    @Test
    void verifyPatToken_suspendedOwner_refused_withoutTouchingLastUsed() {
        String usrId = store.createUser().id();
        CreatePatResult p = pat(usrId);
        store.suspendUser(usrId);

        assertThrows(InvalidPatTokenError.class, () -> store.verifyPatToken(p.token()));
        PersonalAccessToken after = store.getPat(p.pat().id());
        assertNull(after.lastUsedAt());
        assertNull(after.revokedAt());

        store.reinstateUser(usrId);
        assertEquals(usrId, store.verifyPatToken(p.token()).usrId());
    }

    @Test
    void createPat_revokedUser_refused_andNoPatCreated() {
        String usrId = store.createUser().id();
        store.revokeUser(usrId);
        PreconditionError err = assertThrows(PreconditionError.class, () -> pat(usrId));
        assertEquals("user_revoked", err.getReason());
        assertTrue(store.listPatsForUser(usrId, new ListPatsOptions(null, 50)).data().isEmpty());
    }

    @Test
    void createPat_suspendedUser_refused_andNoPatCreated() {
        String usrId = store.createUser().id();
        store.suspendUser(usrId);
        PreconditionError err = assertThrows(PreconditionError.class, () -> pat(usrId));
        assertEquals("user_suspended", err.getReason());
        assertTrue(store.listPatsForUser(usrId, new ListPatsOptions(null, 50)).data().isEmpty());
    }

    @Test
    void verifyMfa_suspendedUser_totpRefused_andStepNotConsumed() {
        Enrolled e = enrolledTotp();
        String c = code(e.secret());
        store.suspendUser(e.usrId());
        InvalidCredentialError err = assertThrows(InvalidCredentialError.class,
                () -> store.verifyMfa(e.usrId(), new TotpProof(c)));
        assertEquals(InvalidCredentialError.class, err.getClass());

        store.reinstateUser(e.usrId());
        store.verifyMfa(e.usrId(), new TotpProof(c));
    }

    @Test
    void verifyMfa_suspendedUser_recoveryRefused_andCodeNotConsumed() {
        String usrId = store.createUser().id();
        RecoveryEnrollmentResult r = store.enrollRecoveryFactor(usrId);
        store.suspendUser(usrId);
        assertThrows(InvalidCredentialError.class,
                () -> store.verifyMfa(usrId, new RecoveryProof(r.codes().get(0))));

        store.reinstateUser(usrId);
        store.verifyMfa(usrId, new RecoveryProof(r.codes().get(0)));
    }

    // ─── Recovery re-enrollment ───

    @Test
    void recovery_reEnrollOverUnexhaustedSet_stillRefused_andSetUnchanged() {
        String usrId = store.createUser().id();
        RecoveryEnrollmentResult first = store.enrollRecoveryFactor(usrId);
        store.verifyMfa(usrId, new RecoveryProof(first.codes().get(0)));

        assertThrows(PreconditionError.class, () -> store.enrollRecoveryFactor(usrId));

        List<Factor> active = store.listMfaFactors(usrId).stream()
                .filter(f -> f.type() == FactorType.RECOVERY && f.status() == FactorStatus.ACTIVE)
                .toList();
        assertEquals(1, active.size());
        assertEquals(first.factor().id(), active.get(0).id());
        store.verifyMfa(usrId, new RecoveryProof(first.codes().get(1)));
    }

    @Test
    void recovery_reEnrollAfterExhaustion_replacesSet() {
        String usrId = store.createUser().id();
        RecoveryEnrollmentResult first = store.enrollRecoveryFactor(usrId);
        for (String code : first.codes()) {
            store.verifyMfa(usrId, new RecoveryProof(code));
        }

        RecoveryEnrollmentResult second = store.enrollRecoveryFactor(usrId);

        List<Factor> active = store.listMfaFactors(usrId).stream()
                .filter(f -> f.type() == FactorType.RECOVERY && f.status() == FactorStatus.ACTIVE)
                .toList();
        assertEquals(List.of(second.factor().id()), active.stream().map(Factor::id).toList());
        assertEquals(FactorStatus.REVOKED, store.getMfaFactor(first.factor().id()).status());
        assertEquals(first.factor().id(), store.getMfaFactor(second.factor().id()).replaces());
        store.verifyMfa(usrId, new RecoveryProof(second.codes().get(0)));
    }
}
