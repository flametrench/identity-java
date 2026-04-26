// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.security.SecureRandom;

/**
 * Recovery code primitives.
 *
 * <p>12-character codes in three groups of four, separated by hyphens.
 * The 31-char alphabet excludes 0/O/1/I/L for reading clarity.
 */
public final class RecoveryCodes {

    public static final int COUNT = 10;
    public static final int LENGTH = 12;
    private static final String ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    private RecoveryCodes() {
        // utility
    }

    /** Generate one fresh 12-char recovery code, formatted XXXX-XXXX-XXXX. */
    public static String generate() {
        StringBuilder chars = new StringBuilder(LENGTH);
        for (int i = 0; i < LENGTH; i++) {
            chars.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return chars.substring(0, 4) + "-" + chars.substring(4, 8) + "-" + chars.substring(8, 12);
    }

    /** Generate a fresh set of 10 recovery codes. */
    public static String[] generateSet() {
        String[] out = new String[COUNT];
        for (int i = 0; i < COUNT; i++) {
            out[i] = generate();
        }
        return out;
    }

    /**
     * Normalize user-input recovery code: uppercase + strip whitespace.
     * Hyphens are preserved.
     */
    public static String normalizeInput(String code) {
        return code.trim().toUpperCase();
    }

    /**
     * Predicate: does {@code code} match the canonical 12-char three-group form?
     *
     * <p>True iff:
     * <ul>
     *   <li>exactly 14 chars (12 alphabet + 2 hyphens)</li>
     *   <li>three groups of four, hyphen-separated</li>
     *   <li>every char from the recovery alphabet (excludes 0/O/1/I/L)</li>
     *   <li>all chars uppercase ASCII</li>
     * </ul>
     */
    public static boolean isValid(String code) {
        if (code == null || code.length() != LENGTH + 2) return false;
        String[] parts = code.split("-", -1);
        if (parts.length != 3) return false;
        for (String part : parts) {
            if (part.length() != 4) return false;
            for (int i = 0; i < part.length(); i++) {
                if (ALPHABET.indexOf(part.charAt(i)) == -1) return false;
            }
        }
        return true;
    }
}
