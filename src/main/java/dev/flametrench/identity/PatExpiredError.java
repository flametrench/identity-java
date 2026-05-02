// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Raised by {@link IdentityStore#verifyPatToken} when the pat row
 * exists, has not been revoked, but is past its expiresAt (ADR 0016).
 */
public class PatExpiredError extends IdentityError {
    public PatExpiredError(String patId) {
        super("personal access token " + patId + " is expired", "pat.expired");
    }
}
