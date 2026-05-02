// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Spec-pinned constants for the PAT primitive (ADR 0016).
 *
 * <p>Implementations MAY enforce tighter caps than these. Adopters
 * SHOULD NOT depend on the floor values being exactly these — read
 * them from the constants below if needed.
 */
public final class PatLimits {

    /**
     * Spec floor: PAT {@code expiresAt} MUST be no more than 365 days
     * from {@code createdAt} when set (ADR 0016 §"Constraints").
     * 365 days = 31,536,000 seconds.
     */
    public static final long MAX_LIFETIME_SECONDS = 365L * 24L * 60L * 60L;

    private PatLimits() {
        // utility
    }
}
