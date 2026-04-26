// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * RFC 6238 Time-based One-Time Password primitives.
 *
 * <p>The algorithm is deterministic and exhaustively spec'd; cross-SDK
 * byte-identical against the same RFC vectors as the Python, Node,
 * and PHP SDKs.
 */
public final class Totp {

    public static final int DEFAULT_PERIOD = 30;
    public static final int DEFAULT_DIGITS = 6;
    public static final String DEFAULT_ALGORITHM = "sha1";

    private static final SecureRandom RANDOM = new SecureRandom();

    private Totp() {
        // utility
    }

    /**
     * Compute the TOTP code for a given secret and timestamp.
     *
     * @param secret raw shared-secret bytes (NOT base32-encoded)
     */
    public static String compute(byte[] secret, long timestamp) {
        return compute(secret, timestamp, DEFAULT_PERIOD, DEFAULT_DIGITS, DEFAULT_ALGORITHM);
    }

    public static String compute(
            byte[] secret,
            long timestamp,
            int period,
            int digits,
            String algorithm
    ) {
        long counter = Math.floorDiv(timestamp, period);
        byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter).array();
        byte[] digest = hmac(secret, counterBytes, algorithm);
        int offset = digest[digest.length - 1] & 0x0F;
        int codeInt =
                ((digest[offset] & 0x7F) << 24)
                | ((digest[offset + 1] & 0xFF) << 16)
                | ((digest[offset + 2] & 0xFF) << 8)
                | (digest[offset + 3] & 0xFF);
        int modulus = (int) Math.pow(10, digits);
        return String.format("%0" + digits + "d", codeInt % modulus);
    }

    /**
     * Verify a candidate TOTP code with drift tolerance.
     *
     * <p>Accepts the current window plus ±{@code driftWindows} surrounding
     * windows (default ±1). Constant-time compared via
     * {@link MessageDigest#isEqual}.
     */
    public static boolean verify(byte[] secret, String candidate) {
        return verify(secret, candidate, System.currentTimeMillis() / 1000,
                DEFAULT_PERIOD, DEFAULT_DIGITS, DEFAULT_ALGORITHM, 1);
    }

    public static boolean verify(byte[] secret, String candidate, long timestamp) {
        return verify(secret, candidate, timestamp,
                DEFAULT_PERIOD, DEFAULT_DIGITS, DEFAULT_ALGORITHM, 1);
    }

    public static boolean verify(
            byte[] secret,
            String candidate,
            long timestamp,
            int period,
            int digits,
            String algorithm,
            int driftWindows
    ) {
        if (candidate == null || candidate.length() != digits) return false;
        for (int i = 0; i < candidate.length(); i++) {
            char c = candidate.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        for (int w = -driftWindows; w <= driftWindows; w++) {
            long ts = timestamp + ((long) w * period);
            String expected = compute(secret, ts, period, digits, algorithm);
            if (MessageDigest.isEqual(
                    expected.getBytes(StandardCharsets.US_ASCII),
                    candidate.getBytes(StandardCharsets.US_ASCII)
            )) {
                return true;
            }
        }
        return false;
    }

    /** Generate a fresh TOTP shared secret. Default 20 bytes per RFC 6238. */
    public static byte[] generateSecret() {
        return generateSecret(20);
    }

    public static byte[] generateSecret(int numBytes) {
        byte[] out = new byte[numBytes];
        RANDOM.nextBytes(out);
        return out;
    }

    /** Build the otpauth:// URI for QR rendering at enrollment. */
    public static String otpauthUri(
            byte[] secret,
            String label,
            String issuer
    ) {
        return otpauthUri(secret, label, issuer, DEFAULT_ALGORITHM, DEFAULT_DIGITS, DEFAULT_PERIOD);
    }

    public static String otpauthUri(
            byte[] secret,
            String label,
            String issuer,
            String algorithm,
            int digits,
            int period
    ) {
        String secretB32 = base32Encode(secret).replaceAll("=+$", "");
        String labelQ = urlEncode(issuer + ":" + label);
        String issuerQ = urlEncode(issuer);
        return "otpauth://totp/" + labelQ
                + "?secret=" + secretB32
                + "&issuer=" + issuerQ
                + "&algorithm=" + algorithm.toUpperCase()
                + "&digits=" + digits
                + "&period=" + period;
    }

    private static byte[] hmac(byte[] secret, byte[] message, String algorithm) {
        String javaAlg = switch (algorithm.toLowerCase()) {
            case "sha1" -> "HmacSHA1";
            case "sha256" -> "HmacSHA256";
            case "sha512" -> "HmacSHA512";
            default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        };
        try {
            Mac mac = Mac.getInstance(javaAlg);
            mac.init(new SecretKeySpec(secret, javaAlg));
            return mac.doFinal(message);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(javaAlg + " not available", e);
        } catch (java.security.InvalidKeyException e) {
            throw new IllegalStateException("Invalid HMAC key", e);
        }
    }

    private static String base32Encode(byte[] buf) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int bits = 0;
        int value = 0;
        StringBuilder out = new StringBuilder();
        for (byte b : buf) {
            value = (value << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                out.append(alphabet.charAt((value >>> (bits - 5)) & 0x1F));
                bits -= 5;
            }
        }
        if (bits > 0) {
            out.append(alphabet.charAt((value << (5 - bits)) & 0x1F));
        }
        while (out.length() % 8 != 0) out.append('=');
        return out.toString();
    }

    private static String urlEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8)
                    // URLEncoder uses + for spaces; otpauth wants %20 for parser compat.
                    .replace("+", "%20");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
