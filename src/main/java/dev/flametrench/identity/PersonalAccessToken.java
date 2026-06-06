// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;
import java.util.List;

/**
 * Server-persisted PAT record (ADR 0016). The secret hash is never
 * returned to callers — only metadata. To obtain the plaintext token
 * call {@link IdentityStore#createPat}; thereafter only the owner's
 * local copy holds the secret.
 */
public record PersonalAccessToken(
        String id,
        String usrId,
        String name,
        List<String> scope,
        PatStatus status,
        Instant expiresAt,
        Instant lastUsedAt,
        Instant revokedAt,
        Instant createdAt,
        Instant updatedAt
) {
    public PersonalAccessToken withRevokedAt(Instant revokedAt, Instant updatedAt) {
        return new PersonalAccessToken(id, usrId, name, scope,
                PatStatus.REVOKED, expiresAt, lastUsedAt, revokedAt, createdAt, updatedAt);
    }

    public PersonalAccessToken withLastUsedAt(Instant lastUsedAt, Instant updatedAt) {
        return new PersonalAccessToken(id, usrId, name, scope,
                status, expiresAt, lastUsedAt, revokedAt, createdAt, updatedAt);
    }
}
