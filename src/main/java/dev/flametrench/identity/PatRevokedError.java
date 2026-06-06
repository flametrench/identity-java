// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/** Raised by {@link IdentityStore#verifyPatToken} when the PAT has been explicitly revoked (ADR 0016). */
public class PatRevokedError extends IdentityError {
    private final String patId;

    public PatRevokedError(String patId) {
        super("personal access token " + patId + " is revoked", "pat.revoked");
        this.patId = patId;
    }

    public String getPatId() {
        return patId;
    }
}
