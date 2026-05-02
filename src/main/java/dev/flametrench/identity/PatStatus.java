// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Lifecycle status of a personal access token (ADR 0016).
 *
 * <p>{@code ACTIVE} — present, not expired, not revoked.
 * <p>{@code EXPIRED} — past expires_at. Terminal.
 * <p>{@code REVOKED} — revokePat called. Terminal.
 *
 * <p>A PAT cannot return to ACTIVE once it leaves it; re-issuance
 * creates a new pat row, NOT a replaces-chain entry. PATs are bearer
 * secrets, not interactive credentials with identity continuity to
 * preserve.
 */
public enum PatStatus {
    ACTIVE,
    EXPIRED,
    REVOKED;

    public String wireValue() {
        return name().toLowerCase();
    }

    public static PatStatus fromWire(String value) {
        return PatStatus.valueOf(value.toUpperCase());
    }
}
