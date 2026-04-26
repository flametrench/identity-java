// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for v0.2 MFA primitives in the Java SDK. Mirrors
 * identity-python/tests/test_mfa.py and the Node + PHP test suites
 * exactly so any drift between SDKs surfaces as a failing test.
 */
class MfaTest {

    private static final byte[] SECRET_SHA1 =
            "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SECRET_SHA256 =
            "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SECRET_SHA512 =
            "1234567890123456789012345678901234567890123456789012345678901234"
                    .getBytes(StandardCharsets.US_ASCII);

    // ─── TOTP RFC 6238 §B vectors ───

    @Test
    void totpSha1RfcVectors() {
        long[][] cases = {
                {59L, -1}, {1111111109L, -1}, {1111111111L, -1},
                {1234567890L, -1}, {2000000000L, -1}, {20000000000L, -1}
        };
        String[] expected = {
                "94287082", "07081804", "14050471",
                "89005924", "69279037", "65353130"
        };
        for (int i = 0; i < cases.length; i++) {
            assertEquals(
                    expected[i],
                    Totp.compute(SECRET_SHA1, cases[i][0], 30, 8, "sha1"),
                    "SHA-1 vector at t=" + cases[i][0]
            );
        }
    }

    @Test
    void totpSha256RfcVectors() {
        long[] times = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[] expected = {
                "46119246", "68084774", "67062674",
                "91819424", "90698825", "77737706"
        };
        for (int i = 0; i < times.length; i++) {
            assertEquals(
                    expected[i],
                    Totp.compute(SECRET_SHA256, times[i], 30, 8, "sha256"),
                    "SHA-256 vector at t=" + times[i]
            );
        }
    }

    @Test
    void totpSha512RfcVectors() {
        long[] times = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[] expected = {
                "90693936", "25091201", "99943326",
                "93441116", "38618901", "47863826"
        };
        for (int i = 0; i < times.length; i++) {
            assertEquals(
                    expected[i],
                    Totp.compute(SECRET_SHA512, times[i], 30, 8, "sha512"),
                    "SHA-512 vector at t=" + times[i]
            );
        }
    }

    // ─── totpVerify ───

    @Test
    void totpVerifyCurrentWindow() {
        long ts = 1234567890;
        String code = Totp.compute(SECRET_SHA1, ts);
        assertTrue(Totp.verify(SECRET_SHA1, code, ts));
    }

    @Test
    void totpVerifyDriftMinusOne() {
        long ts = 1234567890;
        String prev = Totp.compute(SECRET_SHA1, ts - Totp.DEFAULT_PERIOD);
        assertTrue(Totp.verify(SECRET_SHA1, prev, ts));
    }

    @Test
    void totpVerifyDriftPlusOne() {
        long ts = 1234567890;
        String next = Totp.compute(SECRET_SHA1, ts + Totp.DEFAULT_PERIOD);
        assertTrue(Totp.verify(SECRET_SHA1, next, ts));
    }

    @Test
    void totpVerifyRejectsTwoWindowsEarlier() {
        long ts = 1234567890;
        String old = Totp.compute(SECRET_SHA1, ts - 2 * Totp.DEFAULT_PERIOD);
        assertFalse(Totp.verify(SECRET_SHA1, old, ts));
    }

    @Test
    void totpVerifyRejectsGarbage() {
        long ts = 1234567890;
        assertFalse(Totp.verify(SECRET_SHA1, "abc", ts));
        assertFalse(Totp.verify(SECRET_SHA1, "", ts));
        assertFalse(Totp.verify(SECRET_SHA1, "12345", ts));
        assertFalse(Totp.verify(SECRET_SHA1, null, ts));
    }

    @Test
    void totpVerifyRejectsWrongCode() {
        assertFalse(Totp.verify(SECRET_SHA1, "000000", 1234567890));
    }

    // ─── secret generation ───

    @Test
    void totpSecretDefaultLengthIs20() {
        assertEquals(20, Totp.generateSecret().length);
    }

    @Test
    void totpSecretsAreUnique() {
        Set<String> set = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            byte[] s = Totp.generateSecret();
            StringBuilder sb = new StringBuilder();
            for (byte b : s) sb.append(String.format("%02x", b));
            set.add(sb.toString());
        }
        assertEquals(50, set.size());
    }

    // ─── otpauth URI ───

    @Test
    void otpauthUriContainsSecretLabelIssuer() {
        String uri = Totp.otpauthUri(
                SECRET_SHA1,
                "alice@example.com",
                "Flametrench"
        );
        assertTrue(uri.startsWith("otpauth://totp/"));
        assertTrue(uri.contains("Flametrench"));
        assertTrue(uri.contains("alice%40example.com"));
        assertTrue(uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
    }

    // ─── recovery codes ───

    @Test
    void recoveryCodeFormat() {
        String code = RecoveryCodes.generate();
        assertEquals(RecoveryCodes.LENGTH + 2, code.length());
        String[] parts = code.split("-");
        assertEquals(3, parts.length);
        for (String p : parts) {
            assertEquals(4, p.length());
        }
    }

    @Test
    void recoveryCodeExcludesAmbiguous() {
        String code = RecoveryCodes.generate();
        for (char ch : "01OIL".toCharArray()) {
            assertEquals(-1, code.indexOf(ch),
                    "found ambiguous char " + ch + " in " + code);
        }
    }

    @Test
    void recoveryCodeSetSize() {
        assertEquals(RecoveryCodes.COUNT, RecoveryCodes.generateSet().length);
    }

    @Test
    void recoveryCodeSetUnique() {
        Set<String> set = new HashSet<>();
        for (String c : RecoveryCodes.generateSet()) set.add(c);
        assertEquals(RecoveryCodes.COUNT, set.size());
    }

    @Test
    void normalizeUppercasesAndStrips() {
        assertEquals("ABCD-EFGH-JKMN",
                RecoveryCodes.normalizeInput("  abcd-efgh-jkmn  "));
    }

    @Test
    void isValidAcceptsCanonical() {
        assertTrue(RecoveryCodes.isValid("ABCD-EFGH-JKMN"));
    }

    @Test
    void isValidRejectsAmbiguous() {
        assertFalse(RecoveryCodes.isValid("ABCD-EFGH-JKM0"));
        assertFalse(RecoveryCodes.isValid("ABCD-EFGH-JKMO"));
        assertFalse(RecoveryCodes.isValid("ABCD-EFGH-JK1N"));
        assertFalse(RecoveryCodes.isValid("ABCD-EFGH-JKMI"));
        assertFalse(RecoveryCodes.isValid("ABCD-EFGH-JKML"));
    }

    @Test
    void isValidRejectsMalformed() {
        assertFalse(RecoveryCodes.isValid("abcd-efgh-jkmn"));
        assertFalse(RecoveryCodes.isValid("ABCDEFGHJKMN"));
        assertFalse(RecoveryCodes.isValid("ABCD-EFGH"));
    }

    // ─── UserMfaPolicy ───

    @Test
    void mfaPolicyRequiredNoGraceIsActive() {
        Instant now = Instant.parse("2026-04-25T12:00:00Z");
        UserMfaPolicy p = new UserMfaPolicy("usr_x", true, null, now);
        assertTrue(p.isActiveNow(now));
    }

    @Test
    void mfaPolicyRequiredFutureGraceIsInactive() {
        Instant now = Instant.parse("2026-04-25T12:00:00Z");
        UserMfaPolicy p = new UserMfaPolicy(
                "usr_x", true,
                Instant.parse("2026-05-01T00:00:00Z"),
                now
        );
        assertFalse(p.isActiveNow(now));
    }

    @Test
    void mfaPolicyRequiredPastGraceIsActive() {
        Instant now = Instant.parse("2026-04-25T12:00:00Z");
        UserMfaPolicy p = new UserMfaPolicy(
                "usr_x", true,
                Instant.parse("2026-04-01T00:00:00Z"),
                now
        );
        assertTrue(p.isActiveNow(now));
    }

    @Test
    void mfaPolicyNotRequiredIsInactive() {
        Instant now = Instant.parse("2026-04-25T12:00:00Z");
        UserMfaPolicy p = new UserMfaPolicy("usr_x", false, null, now);
        assertFalse(p.isActiveNow(now));
    }
}
