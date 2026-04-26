// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;

/**
 * Per-user MFA enforcement policy.
 *
 * <p>When {@code required} is true and {@code graceUntil} is null or
 * past, {@code verifyPassword} produces an MFA-required signal instead
 * of minting a session directly.
 */
public record UserMfaPolicy(
        String usrId,
        boolean required,
        Instant graceUntil,
        Instant updatedAt
) {
    /** True when MFA enforcement is active for this user as of {@code now}. */
    public boolean isActiveNow(Instant now) {
        if (!required) return false;
        if (graceUntil == null) return true;
        return !now.isBefore(graceUntil);
    }
}
