// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/** Raised by {@link IdentityStore#verifyPatToken} for structural failures and wrong secrets (ADR 0016). */
public class InvalidPatTokenError extends IdentityError {
    public InvalidPatTokenError() {
        super("invalid personal access token", "pat.invalid");
    }
}
