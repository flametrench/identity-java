// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Raised by {@link IdentityStore#verifyPatToken} when the pat row
 * exists but has been explicitly revoked via revokePat (ADR 0016).
 * Terminal: a revoked pat cannot return to active.
 */
public class PatRevokedError extends IdentityError {
    public PatRevokedError(String patId) {
        super("personal access token " + patId + " is revoked", "pat.revoked");
    }
}
