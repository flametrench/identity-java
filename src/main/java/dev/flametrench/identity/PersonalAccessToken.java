// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;
import java.util.List;

/**
 * Server-persisted personal access token record (ADR 0016).
 *
 * <p>The plaintext secret is NEVER carried on this object — it leaves
 * the server exactly once, in {@link CreatePatResult} returned by
 * {@link IdentityStore#createPat}. Thereafter only the owner's local
 * copy holds the secret; the server retains an Argon2id hash at the
 * cred-password parameter floor.
 *
 * @param id wire-format pat id (pat_<32hex>)
 * @param usrId wire-format usr id of the owner
 * @param name human-readable label, 1–120 chars
 * @param scope application-defined scope claims; may be empty
 * @param status derived status (ACTIVE / EXPIRED / REVOKED)
 * @param expiresAt optional expiry; null means no expiry
 * @param lastUsedAt last successful verifyPatToken; null if never used
 * @param revokedAt when revokePat was called; null if active or expired
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
) {}
