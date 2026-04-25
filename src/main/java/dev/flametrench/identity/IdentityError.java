// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/** Base class for every identity-layer error. */
public class IdentityError extends RuntimeException {
    private final String code;

    public IdentityError(String message, String code) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
