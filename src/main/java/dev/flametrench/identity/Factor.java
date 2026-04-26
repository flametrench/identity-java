// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;

/**
 * Sealed marker for the three v0.2 factor variants. Switch over the
 * concrete subtype to dispatch in calling code.
 */
public sealed interface Factor permits TotpFactor, WebAuthnFactor, RecoveryFactor {
    String id();
    String usrId();
    FactorStatus status();
    String replaces();
    Instant createdAt();
    Instant updatedAt();
    FactorType type();
}
