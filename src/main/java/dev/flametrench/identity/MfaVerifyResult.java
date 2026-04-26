// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;

/**
 * Successful {@link IdentityStore#verifyMfa} outcome.
 *
 * <p>{@code newSignCount} is set only for WebAuthn proofs (Long; null
 * for TOTP and recovery). {@code mfaVerifiedAt} is the timestamp the
 * SDK stamps on the session (per ADR 0008 {@code ses.mfa_verified_at}).
 */
public record MfaVerifyResult(
        String mfaId,
        FactorType type,
        Instant mfaVerifiedAt,
        Long newSignCount
) {}
