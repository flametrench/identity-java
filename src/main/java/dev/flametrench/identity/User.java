// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;

public record User(
        String id,
        Status status,
        Instant createdAt,
        Instant updatedAt,
        /** v0.2 (ADR 0014) — optional human-meaningful render string. */
        String displayName
) {
    public User withStatus(Status status, Instant updatedAt) {
        return new User(id, status, createdAt, updatedAt, displayName);
    }

    public User withDisplayName(String displayName, Instant updatedAt) {
        return new User(id, status, createdAt, updatedAt, displayName);
    }
}
