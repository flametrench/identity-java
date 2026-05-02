// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Raised by {@link IdentityStore#verifyPatToken} when the bearer is
 * malformed, references a non-existent pat row, OR carries the wrong
 * secret (ADR 0016).
 *
 * <p>The "no such row" and "wrong secret" cases MUST conflate to this
 * single error class with an identical message — distinguishable
 * errors leak token-presence as a timing oracle. See ADR 0016
 * §"Verification semantics".
 */
public class InvalidPatTokenError extends IdentityError {
    public InvalidPatTokenError() {
        super("invalid personal access token", "pat.invalid");
    }

    public InvalidPatTokenError(String message) {
        super(message, "pat.invalid");
    }
}
