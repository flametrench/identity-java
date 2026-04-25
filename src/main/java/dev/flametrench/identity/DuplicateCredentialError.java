// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

public class DuplicateCredentialError extends IdentityError {
    public DuplicateCredentialError(String message) {
        super(message, "conflict.duplicate_credential");
    }
}
