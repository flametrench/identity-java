// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;

public record TotpFactor(
        String id,
        String usrId,
        String identifier,
        FactorStatus status,
        String replaces,
        Instant createdAt,
        Instant updatedAt
) implements Factor {
    @Override
    public FactorType type() { return FactorType.TOTP; }
}
