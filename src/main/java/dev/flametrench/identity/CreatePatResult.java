// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Returned from {@link IdentityStore#createPat} (ADR 0016).
 *
 * <p>The plaintext {@code token} is returned ONCE in this result; the
 * server retains only an Argon2id hash. Callers MUST surface the token
 * to the user immediately and never persist it server-side.
 *
 * @param pat the persisted record (no secret material)
 * @param token the plaintext bearer in
 *     {@code pat_<32hex-id>_<base64url-secret>} form
 */
public record CreatePatResult(PersonalAccessToken pat, String token) {}
