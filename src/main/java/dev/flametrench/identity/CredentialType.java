// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/** The three credential variants supported in v0.1. */
public enum CredentialType {
    PASSWORD("password"),
    PASSKEY("passkey"),
    OIDC("oidc");

    private final String value;

    CredentialType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
