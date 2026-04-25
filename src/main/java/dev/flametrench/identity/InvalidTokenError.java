// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

public class InvalidTokenError extends IdentityError {
    public InvalidTokenError() {
        super("Invalid token", "invalid_token");
    }

    public InvalidTokenError(String message) {
        super(message, "invalid_token");
    }
}
