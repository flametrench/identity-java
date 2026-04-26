// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

/**
 * Low-level Argon2id password-hashing primitives.
 *
 * <p>Use these when you need to hash or verify a password independently
 * of the IdentityStore — e.g., to bridge legacy password stores into the
 * Flametrench identity layer, or to satisfy the cross-language
 * conformance fixture
 * ({@code spec/conformance/fixtures/identity/argon2id.json}).
 *
 * <p>Cross-language interop contract: a PHC-encoded Argon2id hash
 * produced by any conforming Flametrench identity SDK MUST verify
 * identically here, regardless of the language or Argon2 binding that
 * produced it.
 */
public final class PasswordHashing {

    /** Spec floor: 19456 KiB memory cost. */
    public static final int MEMORY_COST = 19456;

    /** Spec floor: 2 iterations. */
    public static final int TIME_COST = 2;

    /** Spec floor: 1 thread. */
    public static final int PARALLELISM = 1;

    /**
     * Hard cap on plaintext password length before Argon2id. Most
     * password managers cap user-input passwords at 256 bytes;
     * legitimate passphrases never need 1024. Without a cap, a caller
     * can pass a multi-megabyte string and burn the Argon2id memory
     * cost (m=19 MiB) repeatedly.
     */
    public static final int MAX_PASSWORD_BYTES = 1024;

    private static final Argon2 ARGON2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

    private PasswordHashing() {
        // utility class
    }

    /**
     * Verify a candidate plaintext password against a PHC-encoded
     * Argon2id hash. Returns false on any verification failure (wrong
     * password, malformed hash, unsupported variant) — never throws on
     * bad input EXCEPT plaintext over {@link #MAX_PASSWORD_BYTES}, which
     * raises {@link IllegalArgumentException} as a caller-side
     * input-validation failure.
     */
    public static boolean verify(String phcHash, String candidatePassword) {
        if (phcHash == null || candidatePassword == null) {
            return false;
        }
        checkPasswordLength(candidatePassword);
        try {
            return ARGON2.verify(phcHash, candidatePassword.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Hash a plaintext password with Argon2id at the spec floor. The
     * returned string is PHC-encoded and verifies against
     * {@link #verify(String, String)} on any conforming SDK. Plaintext
     * over {@link #MAX_PASSWORD_BYTES} raises IllegalArgumentException.
     */
    public static String hash(String plaintext) {
        checkPasswordLength(plaintext);
        // argon2-jvm's hash signature is (iterations, memory, parallelism, password).
        return ARGON2.hash(TIME_COST, MEMORY_COST, PARALLELISM, plaintext.toCharArray());
    }

    private static void checkPasswordLength(String plaintext) {
        int byteLength = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        if (byteLength > MAX_PASSWORD_BYTES) {
            throw new IllegalArgumentException(
                    "password exceeds " + MAX_PASSWORD_BYTES
                            + "-byte cap (got " + byteLength + " bytes)"
            );
        }
    }
}
