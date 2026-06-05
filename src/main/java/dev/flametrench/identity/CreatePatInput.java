// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;
import java.util.List;

/** Request payload for {@link IdentityStore#createPat} (ADR 0016). */
public record CreatePatInput(
        String usrId,
        String name,
        List<String> scope,
        Instant expiresAt
) {}
