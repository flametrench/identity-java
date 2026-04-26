// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Returned by {@link IdentityStore#enrollTotpFactor}.
 *
 * <p>The factor is in {@code pending} status until
 * {@link IdentityStore#confirmTotpFactor}. {@code secretB32} and
 * {@code otpauthUri} are returned ONCE for QR rendering; the SDK
 * retains the raw secret internally and never re-emits it.
 */
public record TotpEnrollmentResult(
        TotpFactor factor,
        String secretB32,
        String otpauthUri
) {}
