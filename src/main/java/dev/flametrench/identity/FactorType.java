// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/** v0.2 factor variants (ADR 0008). */
public enum FactorType {
    TOTP("totp"),
    WEBAUTHN("webauthn"),
    RECOVERY("recovery");

    private final String value;

    FactorType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
