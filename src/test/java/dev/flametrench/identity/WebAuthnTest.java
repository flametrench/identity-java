// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

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
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for v0.2 WebAuthn primitives.
 *
 * <p>Cross-SDK parity is enforced by the conformance corpus; these
 * tests cover the in-SDK pieces the fixtures don't pin (error reasons,
 * COSE-key edge cases, helpers).
 */
class WebAuthnTest {

    private static final String RP_ID = "test.example";
    private static final String ORIGIN = "https://test.example";
    private static final byte[] CHALLENGE = "unit-test-challenge".getBytes(StandardCharsets.UTF_8);

    private record Keypair(PrivateKey privateKey, byte[] cose) {}

    private static Keypair buildKeypair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = gen.generateKeyPair();
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        byte[] x = padTo32(pub.getW().getAffineX().toByteArray());
        byte[] y = padTo32(pub.getW().getAffineY().toByteArray());
        return new Keypair(kp.getPrivate(), WebAuthn.coseKeyEs256(x, y));
    }

    private static byte[] padTo32(byte[] coord) {
        if (coord.length == 32) return coord;
        if (coord.length == 33 && coord[0] == 0) {
            byte[] out = new byte[32];
            System.arraycopy(coord, 1, out, 0, 32);
            return out;
        }
        if (coord.length < 32) {
            byte[] out = new byte[32];
            System.arraycopy(coord, 0, out, 32 - coord.length, coord.length);
            return out;
        }
        throw new IllegalStateException("Coordinate longer than 32 bytes: " + coord.length);
    }

    private static byte[] makeAuthData(String rpId, int flags, int signCount) throws Exception {
        byte[] rpHash = MessageDigest.getInstance("SHA-256")
                .digest(rpId.getBytes(StandardCharsets.UTF_8));
        ByteBuffer buf = ByteBuffer.allocate(37);
        buf.put(rpHash);
        buf.put((byte) flags);
        buf.putInt(signCount);
        return buf.array();
    }

    private static byte[] makeAuthData(int flags, int signCount) throws Exception {
        return makeAuthData(RP_ID, flags, signCount);
    }

    private static byte[] makeClientData(byte[] challenge, String origin, String type) {
        String challengeB64u = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);
        // Sort keys lexicographically (challenge < origin < type) so the JSON
        // is deterministic — matches the Python reference fixture format.
        String json = "{\"challenge\":\"" + challengeB64u + "\",\"origin\":\"" + origin
                + "\",\"type\":\"" + type + "\"}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] sign(PrivateKey privateKey, byte[] authData, byte[] clientData) throws Exception {
        byte[] clientHash = MessageDigest.getInstance("SHA-256").digest(clientData);
        byte[] signed = new byte[authData.length + clientHash.length];
        System.arraycopy(authData, 0, signed, 0, authData.length);
        System.arraycopy(clientHash, 0, signed, authData.length, clientHash.length);
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(privateKey);
        s.update(signed);
        return s.sign();
    }

    @Test
    void verifiesWellFormedAssertion() throws Exception {
        Keypair kp = buildKeypair();
        byte[] auth = makeAuthData(0x05, 42);
        byte[] client = makeClientData(CHALLENGE, ORIGIN, "webauthn.get");
        byte[] sig = sign(kp.privateKey(), auth, client);
        WebAuthnAssertionResult result = WebAuthn.verifyAssertion(
                kp.cose(), 10, RP_ID, CHALLENGE, ORIGIN, auth, client, sig
        );
        assertEquals(42L, result.newSignCount());
    }

    @Test
    void bothZeroCounterAccepted() throws Exception {
        Keypair kp = buildKeypair();
        byte[] auth = makeAuthData(0x05, 0);
        byte[] client = makeClientData(CHALLENGE, ORIGIN, "webauthn.get");
        byte[] sig = sign(kp.privateKey(), auth, client);
        WebAuthnAssertionResult result = WebAuthn.verifyAssertion(
                kp.cose(), 0, RP_ID, CHALLENGE, ORIGIN, auth, client, sig
        );
        assertEquals(0L, result.newSignCount());
    }

    @Test
    void equalCounterRejected() throws Exception {
        Keypair kp = buildKeypair();
        byte[] auth = makeAuthData(0x05, 10);
        byte[] client = makeClientData(CHALLENGE, ORIGIN, "webauthn.get");
        byte[] sig = sign(kp.privateKey(), auth, client);
        WebAuthnError err = assertThrows(WebAuthnError.class, () ->
                WebAuthn.verifyAssertion(kp.cose(), 10, RP_ID, CHALLENGE, ORIGIN, auth, client, sig));
        assertEquals("counter_regression", err.getReason());
    }

    @Test
    void uvRequiredByDefault() throws Exception {
        Keypair kp = buildKeypair();
        byte[] auth = makeAuthData(0x01, 2);
        byte[] client = makeClientData(CHALLENGE, ORIGIN, "webauthn.get");
        byte[] sig = sign(kp.privateKey(), auth, client);
        WebAuthnError err = assertThrows(WebAuthnError.class, () ->
                WebAuthn.verifyAssertion(kp.cose(), 1, RP_ID, CHALLENGE, ORIGIN, auth, client, sig));
        assertEquals("user_not_verified", err.getReason());
    }

    @Test
    void upRequiredByDefault() throws Exception {
        Keypair kp = buildKeypair();
        byte[] auth = makeAuthData(0x04, 2);
        byte[] client = makeClientData(CHALLENGE, ORIGIN, "webauthn.get");
        byte[] sig = sign(kp.privateKey(), auth, client);
        WebAuthnError err = assertThrows(WebAuthnError.class, () ->
                WebAuthn.verifyAssertion(kp.cose(), 1, RP_ID, CHALLENGE, ORIGIN, auth, client, sig));
        assertEquals("user_not_present", err.getReason());
    }

    @Test
    void uvCanBeDisabled() throws Exception {
        Keypair kp = buildKeypair();
        byte[] auth = makeAuthData(0x01, 2);
        byte[] client = makeClientData(CHALLENGE, ORIGIN, "webauthn.get");
        byte[] sig = sign(kp.privateKey(), auth, client);
        WebAuthnAssertionResult result = WebAuthn.verifyAssertion(
                kp.cose(), 1, RP_ID, CHALLENGE, ORIGIN, auth, client, sig, false, true
        );
        assertEquals(2L, result.newSignCount());
    }

    @Test
    void rpIdMismatch() throws Exception {
        Keypair kp = buildKeypair();
        byte[] auth = makeAuthData("evil.test", 0x05, 2);
        byte[] client = makeClientData(CHALLENGE, ORIGIN, "webauthn.get");
        byte[] sig = sign(kp.privateKey(), auth, client);
        WebAuthnError err = assertThrows(WebAuthnError.class, () ->
                WebAuthn.verifyAssertion(kp.cose(), 1, RP_ID, CHALLENGE, ORIGIN, auth, client, sig));
        assertEquals("rp_id_mismatch", err.getReason());
    }

    @Test
    void originMismatch() throws Exception {
        Keypair kp = buildKeypair();
        byte[] auth = makeAuthData(0x05, 2);
        byte[] client = makeClientData(CHALLENGE, "https://evil.test", "webauthn.get");
        byte[] sig = sign(kp.privateKey(), auth, client);
        WebAuthnError err = assertThrows(WebAuthnError.class, () ->
                WebAuthn.verifyAssertion(kp.cose(), 1, RP_ID, CHALLENGE, ORIGIN, auth, client, sig));
        assertEquals("origin_mismatch", err.getReason());
    }

    @Test
    void challengeMismatch() throws Exception {
        Keypair kp = buildKeypair();
        byte[] auth = makeAuthData(0x05, 2);
        byte[] client = makeClientData("different".getBytes(StandardCharsets.UTF_8), ORIGIN, "webauthn.get");
        byte[] sig = sign(kp.privateKey(), auth, client);
        WebAuthnError err = assertThrows(WebAuthnError.class, () ->
                WebAuthn.verifyAssertion(kp.cose(), 1, RP_ID, CHALLENGE, ORIGIN, auth, client, sig));
        assertEquals("challenge_mismatch", err.getReason());
    }

    @Test
    void typeMustBeWebauthnGet() throws Exception {
        Keypair kp = buildKeypair();
        byte[] auth = makeAuthData(0x05, 2);
        byte[] client = makeClientData(CHALLENGE, ORIGIN, "webauthn.create");
        byte[] sig = sign(kp.privateKey(), auth, client);
        WebAuthnError err = assertThrows(WebAuthnError.class, () ->
                WebAuthn.verifyAssertion(kp.cose(), 1, RP_ID, CHALLENGE, ORIGIN, auth, client, sig));
        assertEquals("type_mismatch", err.getReason());
    }

    @Test
    void tamperedSignatureRejected() throws Exception {
        Keypair kp = buildKeypair();
        byte[] auth = makeAuthData(0x05, 2);
        byte[] client = makeClientData(CHALLENGE, ORIGIN, "webauthn.get");
        byte[] sig = sign(kp.privateKey(), auth, client);
        sig[sig.length - 1] ^= 0x01;
        WebAuthnError err = assertThrows(WebAuthnError.class, () ->
                WebAuthn.verifyAssertion(kp.cose(), 1, RP_ID, CHALLENGE, ORIGIN, auth, client, sig));
        assertEquals("signature_invalid", err.getReason());
    }

    @Test
    void truncatedAuthenticatorData() throws Exception {
        Keypair kp = buildKeypair();
        WebAuthnError err = assertThrows(WebAuthnError.class, () ->
                WebAuthn.verifyAssertion(
                        kp.cose(), 0, RP_ID, CHALLENGE, ORIGIN,
                        new byte[10],
                        makeClientData(CHALLENGE, ORIGIN, "webauthn.get"),
                        new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}
                ));
        assertEquals("malformed", err.getReason());
    }

    @Test
    void unsupportedCoseKty() throws Exception {
        // OKP key (kty=1) — not supported in v0.2.
        byte[] bad = new byte[1 + 2 + 2 + 2 + 3 + 32 + 3 + 32];
        bad[0] = (byte) 0xA5;
        bad[1] = 0x01;
        bad[2] = 0x01;
        bad[3] = 0x03;
        bad[4] = 0x26;
        bad[5] = 0x20;
        bad[6] = 0x01;
        bad[7] = 0x21;
        bad[8] = 0x58;
        bad[9] = 0x20;
        bad[42] = 0x22;
        bad[43] = 0x58;
        bad[44] = 0x20;
        WebAuthnError err = assertThrows(WebAuthnError.class, () ->
                WebAuthn.verifyAssertion(
                        bad, 0, RP_ID, CHALLENGE, ORIGIN,
                        makeAuthData(0x05, 1),
                        makeClientData(CHALLENGE, ORIGIN, "webauthn.get"),
                        new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}
                ));
        assertEquals("unsupported_key", err.getReason());
    }

    @Test
    void errorCodeCarriesWebauthnPrefix() {
        WebAuthnError err = new WebAuthnError("boom", "signature_invalid");
        assertEquals("webauthn.signature_invalid", err.getCode());
        assertEquals("signature_invalid", err.getReason());
    }
}
