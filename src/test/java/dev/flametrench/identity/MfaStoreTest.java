// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for v0.2 IdentityStore MFA operations. Cross-SDK parity
 * is enforced by the conformance corpus and the per-primitive tests
 * (TOTP RFC vectors, WebAuthn signature verification, recovery format).
 * This file focuses on store-level orchestration that ADR 0008 specifies.
 */
class MfaStoreTest {

    private InMemoryIdentityStore store;
    private AtomicReference<Instant> mockTime;

    @BeforeEach
    void setup() {
        mockTime = new AtomicReference<>(Instant.parse("2026-04-26T12:00:00Z"));
        Clock mockClock = new Clock() {
            @Override public Instant instant() { return mockTime.get(); }
            @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId z) { return this; }
        };
        store = new InMemoryIdentityStore(mockClock);
    }

    private void advance(long seconds) {
        mockTime.set(mockTime.get().plusSeconds(seconds));
    }

    private static byte[] decodeBase32(String s) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        String clean = s.replaceAll("=+$", "");
        int bits = 0, value = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (char c : clean.toCharArray()) {
            int idx = alphabet.indexOf(c);
            if (idx < 0) throw new IllegalArgumentException("bad base32 char " + c);
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) {
                out.write((value >>> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }

    // ─── Recovery codes ─────────────────────────────────────────

    @Test
    void recoveryEnrollmentReturns10ActiveCodes() {
        User user = store.createUser();
        RecoveryEnrollmentResult result = store.enrollRecoveryFactor(user.id());
        assertEquals(FactorStatus.ACTIVE, result.factor().status());
        assertEquals(10, result.codes().size());
        assertEquals(10, result.factor().remaining());
        for (String c : result.codes()) {
            assertTrue(RecoveryCodes.isValid(c));
        }
    }

    @Test
    void recoveryVerifyConsumesSlot() {
        User user = store.createUser();
        RecoveryEnrollmentResult enroll = store.enrollRecoveryFactor(user.id());
        String code = enroll.codes().get(3);
        store.verifyMfa(user.id(), new RecoveryProof(code));
        assertThrows(InvalidCredentialError.class,
                () -> store.verifyMfa(user.id(), new RecoveryProof(code)));
        Factor refreshed = store.getMfaFactor(enroll.factor().id());
        assertEquals(9, ((RecoveryFactor) refreshed).remaining());
    }

    @Test
    void recoveryVerifyNormalizes() {
        User user = store.createUser();
        RecoveryEnrollmentResult enroll = store.enrollRecoveryFactor(user.id());
        store.verifyMfa(user.id(),
                new RecoveryProof("  " + enroll.codes().get(0).toLowerCase() + "  "));
    }

    @Test
    void recoveryAtMostOneActivePerUser() {
        User user = store.createUser();
        store.enrollRecoveryFactor(user.id());
        assertThrows(PreconditionError.class,
                () -> store.enrollRecoveryFactor(user.id()));
    }

    @Test
    void recoveryRevokeFreesSingleton() {
        User user = store.createUser();
        RecoveryEnrollmentResult first = store.enrollRecoveryFactor(user.id());
        store.revokeMfaFactor(first.factor().id());
        RecoveryEnrollmentResult second = store.enrollRecoveryFactor(user.id());
        assertNotEquals(first.factor().id(), second.factor().id());
    }

    // ─── TOTP ────────────────────────────────────────────────────

    @Test
    void totpEnrollmentReturnsPendingFactor() {
        User user = store.createUser();
        TotpEnrollmentResult enroll = store.enrollTotpFactor(user.id(), "iPhone");
        assertEquals(FactorStatus.PENDING, enroll.factor().status());
        assertTrue(enroll.secretB32().matches("^[A-Z2-7]+$"));
        assertTrue(enroll.otpauthUri().startsWith("otpauth://totp/"));
    }

    @Test
    void totpConfirmActivatesWithCorrectCode() {
        User user = store.createUser();
        TotpEnrollmentResult enroll = store.enrollTotpFactor(user.id(), "iPhone");
        byte[] secret = decodeBase32(enroll.secretB32());
        String code = Totp.compute(secret, mockTime.get().getEpochSecond());
        TotpFactor confirmed = store.confirmTotpFactor(enroll.factor().id(), code);
        assertEquals(FactorStatus.ACTIVE, confirmed.status());
    }

    @Test
    void totpConfirmRejectsWrongCode() {
        User user = store.createUser();
        TotpEnrollmentResult enroll = store.enrollTotpFactor(user.id(), "iPhone");
        assertThrows(InvalidCredentialError.class,
                () -> store.confirmTotpFactor(enroll.factor().id(), "000000"));
    }

    @Test
    void totpConfirmAfterPendingTtlRejects() {
        User user = store.createUser();
        TotpEnrollmentResult enroll = store.enrollTotpFactor(user.id(), "iPhone");
        advance(700);
        byte[] secret = decodeBase32(enroll.secretB32());
        String code = Totp.compute(secret, mockTime.get().getEpochSecond());
        PreconditionError err = assertThrows(PreconditionError.class,
                () -> store.confirmTotpFactor(enroll.factor().id(), code));
        assertEquals("pending_factor_expired", err.getReason());
    }

    @Test
    void totpAtMostOneActivePerUserAfterConfirm() {
        User user = store.createUser();
        TotpEnrollmentResult enroll = store.enrollTotpFactor(user.id(), "iPhone");
        byte[] secret = decodeBase32(enroll.secretB32());
        store.confirmTotpFactor(enroll.factor().id(),
                Totp.compute(secret, mockTime.get().getEpochSecond()));
        assertThrows(PreconditionError.class,
                () -> store.enrollTotpFactor(user.id(), "Backup"));
    }

    @Test
    void totpVerifyAfterConfirm() {
        User user = store.createUser();
        TotpEnrollmentResult enroll = store.enrollTotpFactor(user.id(), "iPhone");
        byte[] secret = decodeBase32(enroll.secretB32());
        store.confirmTotpFactor(enroll.factor().id(),
                Totp.compute(secret, mockTime.get().getEpochSecond()));
        MfaVerifyResult result = store.verifyMfa(user.id(),
                new TotpProof(Totp.compute(secret, mockTime.get().getEpochSecond())));
        assertEquals(FactorType.TOTP, result.type());
        assertEquals(enroll.factor().id(), result.mfaId());
    }

    @Test
    void totpVerifyWithNoActiveFactorRejects() {
        User user = store.createUser();
        assertThrows(InvalidCredentialError.class,
                () -> store.verifyMfa(user.id(), new TotpProof("123456")));
    }

    // ─── WebAuthn ────────────────────────────────────────────────

    private static byte[] padTo32(byte[] coord) {
        if (coord.length == 32) return coord;
        if (coord.length == 33 && coord[0] == 0) {
            byte[] out = new byte[32];
            System.arraycopy(coord, 1, out, 0, 32);
            return out;
        }
        byte[] out = new byte[32];
        System.arraycopy(coord, 0, out, 32 - coord.length, coord.length);
        return out;
    }

    private static record Keypair(PrivateKey privateKey, byte[] cose) {}

    private static Keypair makeKeypair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = gen.generateKeyPair();
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        byte[] x = padTo32(pub.getW().getAffineX().toByteArray());
        byte[] y = padTo32(pub.getW().getAffineY().toByteArray());
        return new Keypair(kp.getPrivate(), WebAuthn.coseKeyEs256(x, y));
    }

    private static record Assertion(byte[] authData, byte[] clientData, byte[] signature) {}

    private static Assertion makeAssertion(
            PrivateKey priv, String rpId, String origin, byte[] challenge, int signCount
    ) throws Exception {
        byte[] rpHash = MessageDigest.getInstance("SHA-256")
                .digest(rpId.getBytes(StandardCharsets.UTF_8));
        ByteBuffer auth = ByteBuffer.allocate(37);
        auth.put(rpHash);
        auth.put((byte) 0x05);
        auth.putInt(signCount);
        byte[] authData = auth.array();
        String b64u = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);
        String json = "{\"challenge\":\"" + b64u + "\",\"origin\":\"" + origin
                + "\",\"type\":\"webauthn.get\"}";
        byte[] clientData = json.getBytes(StandardCharsets.UTF_8);
        byte[] clientHash = MessageDigest.getInstance("SHA-256").digest(clientData);
        byte[] signed = new byte[authData.length + clientHash.length];
        System.arraycopy(authData, 0, signed, 0, authData.length);
        System.arraycopy(clientHash, 0, signed, authData.length, clientHash.length);
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(priv);
        s.update(signed);
        return new Assertion(authData, clientData, s.sign());
    }

    @Test
    void webauthnEnrollConfirmVerifyAdvancesCounter() throws Exception {
        User user = store.createUser();
        Keypair kp = makeKeypair();
        String credId = "test-credential-id";
        String rpId = "test.example";
        String origin = "https://test.example";
        WebAuthnEnrollmentResult enroll = store.enrollWebAuthnFactor(
                user.id(), credId, kp.cose(), 0, rpId);
        assertEquals(FactorStatus.PENDING, enroll.factor().status());
        Assertion a1 = makeAssertion(kp.privateKey(), rpId, origin,
                "confirm-challenge".getBytes(StandardCharsets.UTF_8), 1);
        WebAuthnFactor confirmed = store.confirmWebAuthnFactor(
                enroll.factor().id(), a1.authData(), a1.clientData(), a1.signature(),
                "confirm-challenge".getBytes(StandardCharsets.UTF_8), origin);
        assertEquals(FactorStatus.ACTIVE, confirmed.status());
        assertEquals(1L, confirmed.signCount());
        Assertion a2 = makeAssertion(kp.privateKey(), rpId, origin,
                "verify-challenge".getBytes(StandardCharsets.UTF_8), 2);
        MfaVerifyResult result = store.verifyMfa(user.id(), new WebAuthnProof(
                credId, a2.authData(), a2.clientData(), a2.signature(),
                "verify-challenge".getBytes(StandardCharsets.UTF_8), origin));
        assertEquals(FactorType.WEBAUTHN, result.type());
        assertEquals(2L, result.newSignCount());
    }

    @Test
    void webauthnMultipleActiveFactorsPermitted() throws Exception {
        User user = store.createUser();
        Keypair k1 = makeKeypair();
        Keypair k2 = makeKeypair();
        WebAuthnEnrollmentResult e1 = store.enrollWebAuthnFactor(user.id(), "cred-a", k1.cose(), 0, "x");
        WebAuthnEnrollmentResult e2 = store.enrollWebAuthnFactor(user.id(), "cred-b", k2.cose(), 0, "x");
        assertNotEquals(e1.factor().id(), e2.factor().id());
    }

    @Test
    void webauthnDuplicateCredentialIdRejects() throws Exception {
        User user = store.createUser();
        Keypair k = makeKeypair();
        store.enrollWebAuthnFactor(user.id(), "dup", k.cose(), 0, "x");
        assertThrows(PreconditionError.class,
                () -> store.enrollWebAuthnFactor(user.id(), "dup", k.cose(), 0, "x"));
    }

    // ─── Listing + policy ───

    @Test
    void listMfaFactorsReturnsUserScoped() {
        User a = store.createUser();
        User b = store.createUser();
        store.enrollRecoveryFactor(a.id());
        store.enrollTotpFactor(a.id(), "iPhone");
        store.enrollRecoveryFactor(b.id());
        assertEquals(2, store.listMfaFactors(a.id()).size());
        assertEquals(1, store.listMfaFactors(b.id()).size());
    }

    @Test
    void mfaPolicyDefaultsToNull() {
        User user = store.createUser();
        assertNull(store.getMfaPolicy(user.id()));
    }

    @Test
    void mfaPolicyRoundTrip() {
        User user = store.createUser();
        Instant grace = Instant.parse("2026-05-10T00:00:00Z");
        UserMfaPolicy policy = store.setMfaPolicy(user.id(), true, grace);
        assertTrue(policy.required());
        assertEquals(grace, policy.graceUntil());
        assertEquals(policy, store.getMfaPolicy(user.id()));
    }

    @Test
    void mfaPolicySetOverwrites() {
        User user = store.createUser();
        store.setMfaPolicy(user.id(), true, null);
        store.setMfaPolicy(user.id(), false, null);
        assertFalse(store.getMfaPolicy(user.id()).required());
    }
}
