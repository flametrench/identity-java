// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

public class SessionExpiredError extends IdentityError {
    public SessionExpiredError(String message) {
        super(message, "session_expired");
    }
}
