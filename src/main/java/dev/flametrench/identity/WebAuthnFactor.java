// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;

public record WebAuthnFactor(
        String id,
        String usrId,
        String identifier,
        FactorStatus status,
        String replaces,
        String rpId,
        long signCount,
        Instant createdAt,
        Instant updatedAt
) implements Factor {
    @Override
    public FactorType type() { return FactorType.WEBAUTHN; }
}
