// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Raised for both unknown identifiers and bad passwords. Message is
 * intentionally generic — don't disclose which arm failed.
 */
public class InvalidCredentialError extends IdentityError {
    public InvalidCredentialError() {
        super("Invalid credential", "invalid_credential");
    }

    public InvalidCredentialError(String message) {
        super(message, "invalid_credential");
    }
}
