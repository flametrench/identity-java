// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Raised by {@link IdentityStore#verifyMfa} and
 * {@link IdentityStore#confirmTotpFactor} when a TOTP code matches a
 * time-step at or before the factor's last accepted step (ADR 0027).
 * Extends {@link InvalidCredentialError} so callers that already treat a
 * failed TOTP proof as an invalid credential keep failing closed.
 */
public class ReplayedTotpError extends InvalidCredentialError {
    public ReplayedTotpError() {
        super("TOTP code was already used", "unauthorized.totp_replayed");
    }
}
