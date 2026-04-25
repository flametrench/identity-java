// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

public class CredentialNotActiveError extends IdentityError {
    public CredentialNotActiveError(String message) {
        super(message, "cred_not_active");
    }
}
