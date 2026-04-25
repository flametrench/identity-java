// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

public class CredentialTypeMismatchError extends IdentityError {
    public CredentialTypeMismatchError(String message) {
        super(message, "cred_type_mismatch");
    }
}
