// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;

/**
 * Recovery-code factor record. Unlike TotpFactor and WebAuthnFactor,
 * recovery factors don't carry a user-facing identifier — they are a
 * set of 10 single-use codes per user. Switch on {@link #type()} to
 * dispatch.
 */
public record RecoveryFactor(
        String id,
        String usrId,
        FactorStatus status,
        String replaces,
        Instant createdAt,
        Instant updatedAt,
        int remaining
) implements Factor {
    @Override
    public FactorType type() { return FactorType.RECOVERY; }
}
