// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Audit {@code auth.kind} discriminator values per ADR 0016 §"Bearer
 * routing".
 *
 * <p>security-audit-v0.3.md F3: pre-fix the four canonical values
 * (pat / share / session / system) lived only in spec prose with no
 * SDK constant. Adopters writing cron / scheduled jobs reach for
 * {@code "pat"} or {@code "session"} because those exist as code
 * values; {@code "system"} (operator-initiated, no human bearer) did
 * not. This enum centralizes the constants so adopters can use
 * {@link AuthKind#SYSTEM} instead of stringly-typing across an audit
 * pipeline.
 *
 * <p>{@code PAT}, {@code SHARE}, and {@code SESSION} are minted by the
 * bearer dispatcher / verifiers; {@code SYSTEM} is set directly by
 * adopter code (cron jobs, batch processors, scheduled tasks).
 */
public enum AuthKind {
    PAT("pat"),
    SHARE("share"),
    SESSION("session"),
    SYSTEM("system");

    private final String value;

    AuthKind(String value) {
        this.value = value;
    }

    /** The canonical wire value for {@code auth.kind} audit fields. */
    public String value() {
        return value;
    }
}
