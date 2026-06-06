// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/** Lifecycle state of a personal access token (ADR 0016). */
public enum PatStatus {
    ACTIVE("active"),
    EXPIRED("expired"),
    REVOKED("revoked");

    private final String value;

    PatStatus(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }
}
