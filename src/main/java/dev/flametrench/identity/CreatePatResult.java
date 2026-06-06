// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Success outcome of {@link IdentityStore#createPat} (ADR 0016).
 * {@code token} is the plaintext bearer — the only chance to capture it.
 */
public record CreatePatResult(PersonalAccessToken pat, String token) {}
