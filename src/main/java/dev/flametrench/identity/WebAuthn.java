// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * WebAuthn assertion verification — v0.2 reference per ADR 0008.
 *
 * <p>Mirrors identity-python's webauthn module so the conformance
 * fixture corpus passes byte-identically across SDKs. Pure-static.
 *
 * <p>Scope (v0.2): ES256 (ECDSA P-256 + SHA-256) only. RS256 + EdDSA
 * are deferred to v0.3.
 */
public final class WebAuthn {

    private static final int FLAG_UP = 0x01;
    private static final int FLAG_UV = 0x04;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final ECParameterSpec P256_PARAMS = loadP256Params();

    private WebAuthn() {
        // utility
    }

    /** Verify a WebAuthn assertion and return the new sign count. */
    public static WebAuthnAssertionResult verifyAssertion(
            byte[] cosePublicKey,
            long storedSignCount,
            String storedRpId,
            byte[] expectedChallenge,
            String expectedOrigin,
            byte[] authenticatorData,
            byte[] clientDataJson,
            byte[] signature,
            boolean requireUserVerified,
            boolean requireUserPresent
    ) {
        // Parse clientDataJSON.
        JsonNode clientData;
        try {
            clientData = MAPPER.readTree(clientDataJson);
        } catch (Exception exc) {
            throw new WebAuthnError(
                    "clientDataJSON not valid JSON: " + exc.getMessage(),
                    "malformed"
            );
        }
        if (!clientData.isObject()) {
            throw new WebAuthnError("clientDataJSON is not an object", "malformed");
        }
        JsonNode typeNode = clientData.get("type");
        if (typeNode == null || !typeNode.isTextual() || !"webauthn.get".equals(typeNode.asText())) {
            throw new WebAuthnError(
                    "clientDataJSON.type must be 'webauthn.get', got " + typeNode,
                    "type_mismatch"
            );
        }
        JsonNode originNode = clientData.get("origin");
        if (originNode == null || !originNode.isTextual() || !expectedOrigin.equals(originNode.asText())) {
            throw new WebAuthnError(
                    "Origin mismatch: expected " + expectedOrigin + ", got " + originNode,
                    "origin_mismatch"
            );
        }
        JsonNode challengeNode = clientData.get("challenge");
        if (challengeNode == null || !challengeNode.isTextual()) {
            throw new WebAuthnError("clientDataJSON.challenge missing", "malformed");
        }
        byte[] challengeBytes;
        try {
            challengeBytes = Base64.getUrlDecoder().decode(challengeNode.asText());
        } catch (IllegalArgumentException exc) {
            throw new WebAuthnError(
                    "clientDataJSON.challenge not base64url: " + exc.getMessage(),
                    "malformed"
            );
        }
        if (!MessageDigest.isEqual(challengeBytes, expectedChallenge)) {
            throw new WebAuthnError("Challenge does not match", "challenge_mismatch");
        }

        // Parse authenticatorData.
        if (authenticatorData.length < 37) {
            throw new WebAuthnError("authenticatorData truncated", "malformed");
        }
        byte[] rpIdHash = new byte[32];
        System.arraycopy(authenticatorData, 0, rpIdHash, 0, 32);
        int flags = authenticatorData[32] & 0xFF;
        long signCount = ByteBuffer.wrap(authenticatorData, 33, 4).getInt() & 0xFFFFFFFFL;

        byte[] expectedRpHash;
        try {
            expectedRpHash = MessageDigest.getInstance("SHA-256")
                    .digest(storedRpId.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("SHA-256 not available", exc);
        }
        if (!MessageDigest.isEqual(rpIdHash, expectedRpHash)) {
            throw new WebAuthnError("RP ID hash does not match", "rp_id_mismatch");
        }
        if (requireUserPresent && (flags & FLAG_UP) == 0) {
            throw new WebAuthnError("User-present flag not set", "user_not_present");
        }
        if (requireUserVerified && (flags & FLAG_UV) == 0) {
            throw new WebAuthnError("User-verified flag not set", "user_not_verified");
        }

        long newSignCount;
        if (signCount == 0 && storedSignCount == 0) {
            newSignCount = 0;
        } else if (signCount > storedSignCount) {
            newSignCount = signCount;
        } else {
            throw new WebAuthnError(
                    "Sign count did not advance: stored=" + storedSignCount + ", got=" + signCount,
                    "counter_regression"
            );
        }

        // Parse COSE_Key, build PublicKey, verify ES256 signature.
        Es256Coords coords = parseCoseEs256(cosePublicKey);
        PublicKey publicKey = buildEs256PublicKey(coords);

        if (signature.length < 8 || (signature[0] & 0xFF) != 0x30) {
            throw new WebAuthnError("Signature is not a DER ECDSA structure", "signature_invalid");
        }

        byte[] clientHash;
        byte[] signed;
        try {
            clientHash = MessageDigest.getInstance("SHA-256").digest(clientDataJson);
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("SHA-256 not available", exc);
        }
        signed = new byte[authenticatorData.length + clientHash.length];
        System.arraycopy(authenticatorData, 0, signed, 0, authenticatorData.length);
        System.arraycopy(clientHash, 0, signed, authenticatorData.length, clientHash.length);

        boolean ok;
        try {
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(signed);
            ok = verifier.verify(signature);
        } catch (GeneralSecurityException exc) {
            // SignatureException is thrown for malformed DER too; treat
            // identically to a verify-returns-false case.
            throw new WebAuthnError(
                    "Signature verification failed: " + exc.getMessage(),
                    "signature_invalid"
            );
        }
        if (!ok) {
            throw new WebAuthnError("Signature verification failed", "signature_invalid");
        }

        return new WebAuthnAssertionResult(newSignCount);
    }

    /** Convenience overload using the v0.2 default (require UV + UP). */
    public static WebAuthnAssertionResult verifyAssertion(
            byte[] cosePublicKey,
            long storedSignCount,
            String storedRpId,
            byte[] expectedChallenge,
            String expectedOrigin,
            byte[] authenticatorData,
            byte[] clientDataJson,
            byte[] signature
    ) {
        return verifyAssertion(
                cosePublicKey, storedSignCount, storedRpId, expectedChallenge,
                expectedOrigin, authenticatorData, clientDataJson, signature,
                true, true
        );
    }

    /**
     * Build a COSE_Key (RFC 8152) for an ES256 / P-256 public key from
     * raw 32-byte x/y coordinates. Useful for fixture authoring.
     */
    public static byte[] coseKeyEs256(byte[] x, byte[] y) {
        if (x.length != 32 || y.length != 32) {
            throw new IllegalArgumentException("ES256 coordinates must be 32 bytes each");
        }
        byte[] out = new byte[1 + 2 + 2 + 2 + 3 + 32 + 3 + 32];
        int off = 0;
        out[off++] = (byte) 0xA5;
        out[off++] = 0x01;
        out[off++] = 0x02;
        out[off++] = 0x03;
        out[off++] = 0x26;
        out[off++] = 0x20;
        out[off++] = 0x01;
        out[off++] = 0x21;
        out[off++] = 0x58;
        out[off++] = 0x20;
        System.arraycopy(x, 0, out, off, 32);
        off += 32;
        out[off++] = 0x22;
        out[off++] = 0x58;
        out[off++] = 0x20;
        System.arraycopy(y, 0, out, off, 32);
        return out;
    }

    public static String b64urlEncode(byte[] buf) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    // ─── internals ─────────────────────────────────────────────

    private record Es256Coords(byte[] x, byte[] y) {}

    private static Es256Coords parseCoseEs256(byte[] coseKey) {
        CborCursor c = new CborCursor(coseKey);
        Object value = decodeItem(c);
        if (c.offset != coseKey.length) {
            throw new WebAuthnError("Trailing bytes after CBOR map", "malformed");
        }
        if (!(value instanceof Map<?, ?> map)) {
            throw new WebAuthnError("Top-level COSE value is not a map", "malformed");
        }
        // CBOR int values come out as Long; look up with Long keys.
        Object kty = map.get(1L);
        Object alg = map.get(3L);
        Object crv = map.get(-1L);
        Object x = map.get(-2L);
        Object y = map.get(-3L);
        if (!(kty instanceof Long ktyL) || ktyL != 2L) {
            throw new WebAuthnError("Unsupported COSE kty: " + kty, "unsupported_key");
        }
        if (!(alg instanceof Long algL) || algL != -7L) {
            throw new WebAuthnError("Unsupported COSE alg: " + alg, "unsupported_key");
        }
        if (!(crv instanceof Long crvL) || crvL != 1L) {
            throw new WebAuthnError("Unsupported COSE crv: " + crv, "unsupported_key");
        }
        if (!(x instanceof byte[] xb) || xb.length != 32) {
            throw new WebAuthnError("COSE x coordinate must be 32 bytes", "malformed");
        }
        if (!(y instanceof byte[] yb) || yb.length != 32) {
            throw new WebAuthnError("COSE y coordinate must be 32 bytes", "malformed");
        }
        return new Es256Coords(xb, yb);
    }

    private static final class CborCursor {
        final byte[] buf;
        int offset;

        CborCursor(byte[] buf) {
            this.buf = buf;
        }

        int readByte() {
            if (offset >= buf.length) {
                throw new WebAuthnError("CBOR truncated", "malformed");
            }
            return buf[offset++] & 0xFF;
        }

        long readUint(int info) {
            if (info < 24) return info;
            if (info == 24) return readByte();
            if (info == 25) {
                int b1 = readByte();
                int b2 = readByte();
                return ((long) b1 << 8) | b2;
            }
            if (info == 26) {
                long b1 = readByte();
                long b2 = readByte();
                long b3 = readByte();
                long b4 = readByte();
                return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
            }
            // 64-bit lengths unrealistic for COSE keys.
            throw new WebAuthnError("Unsupported CBOR length encoding", "malformed");
        }

        byte[] readBytes(int length) {
            if (offset + length > buf.length) {
                throw new WebAuthnError("CBOR truncated", "malformed");
            }
            byte[] out = new byte[length];
            System.arraycopy(buf, offset, out, 0, length);
            offset += length;
            return out;
        }
    }

    private static Object decodeItem(CborCursor c) {
        int first = c.readByte();
        int major = first >> 5;
        int info = first & 0x1F;
        if (major == 0) {
            return c.readUint(info);
        }
        if (major == 1) {
            return -1L - c.readUint(info);
        }
        if (major == 2) {
            int length = (int) c.readUint(info);
            return c.readBytes(length);
        }
        if (major == 5) {
            int length = (int) c.readUint(info);
            Map<Object, Object> out = new HashMap<>();
            for (int i = 0; i < length; i++) {
                Object key = decodeItem(c);
                Object value = decodeItem(c);
                if (!(key instanceof Long)) {
                    throw new WebAuthnError("Non-int CBOR map key", "malformed");
                }
                out.put(key, value);
            }
            return out;
        }
        throw new WebAuthnError("Unsupported CBOR major type: " + major, "malformed");
    }

    private static PublicKey buildEs256PublicKey(Es256Coords coords) {
        try {
            ECPoint point = new ECPoint(
                    new BigInteger(1, coords.x()),
                    new BigInteger(1, coords.y())
            );
            ECPublicKeySpec spec = new ECPublicKeySpec(point, P256_PARAMS);
            return KeyFactory.getInstance("EC").generatePublic(spec);
        } catch (GeneralSecurityException exc) {
            throw new WebAuthnError(
                    "Could not construct P-256 public key: " + exc.getMessage(),
                    "malformed"
            );
        }
    }

    private static ECParameterSpec loadP256Params() {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("secp256r1 not available", exc);
        }
    }
}
