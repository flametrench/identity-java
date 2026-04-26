// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Lifecycle status of a single factor.
 *
 * <p>{@code PENDING} — for TOTP/WebAuthn between enroll and confirm.
 * {@code ACTIVE} — usable for verifyMfa. Recovery codes start active.
 * {@code SUSPENDED} / {@code REVOKED} — terminal-ish per ADR 0005 lifecycle.
 */
public enum FactorStatus {
    PENDING("pending"),
    ACTIVE("active"),
    SUSPENDED("suspended"),
    REVOKED("revoked");

    private final String value;

    FactorStatus(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
