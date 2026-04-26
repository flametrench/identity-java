// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.util.List;

/**
 * Returned by {@link IdentityStore#enrollRecoveryFactor}.
 *
 * <p>Factor is active immediately. {@code codes} is the plaintext set
 * returned ONCE — the SDK stores Argon2id hashes only.
 */
public record RecoveryEnrollmentResult(RecoveryFactor factor, List<String> codes) {}
