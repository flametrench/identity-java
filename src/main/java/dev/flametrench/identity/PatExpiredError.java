// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/** Raised by {@link IdentityStore#verifyPatToken} when the PAT is past {@code expires_at} (ADR 0016). */
public class PatExpiredError extends IdentityError {
    private final String patId;

    public PatExpiredError(String patId) {
        super("personal access token " + patId + " is expired", "pat.expired");
        this.patId = patId;
    }

    public String getPatId() {
        return patId;
    }
}
