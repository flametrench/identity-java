// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;

public record Session(
        String id,
        String usrId,
        String credId,
        Instant createdAt,
        Instant expiresAt,
        Instant revokedAt
) {
    public Session withRevokedAt(Instant at) {
        return new Session(id, usrId, credId, createdAt, expiresAt, at);
    }
}
