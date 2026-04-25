// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

public class NotFoundError extends IdentityError {
    public NotFoundError(String message) {
        super(message, "not_found");
    }
}
