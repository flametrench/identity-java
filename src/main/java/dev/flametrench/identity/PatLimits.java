// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Spec-pinned constants for the PAT primitive (ADR 0016).
 *
 * <p>Implementations MAY enforce tighter caps than these. Adopters
 * SHOULD NOT depend on the floor values being exactly these — read
 * them from the constants below if needed.
 */
public final class PatLimits {

    /**
     * Spec floor: PAT {@code expiresAt} MUST be no more than 365 days
     * from {@code createdAt} when set (ADR 0016 §"Constraints").
     * 365 days = 31,536,000 seconds.
     */
    public static final long MAX_LIFETIME_SECONDS = 365L * 24L * 60L * 60L;

    /**
     * security-audit-v0.3.md H2 — the dummy PHC hash used by
     * {@code verifyPatToken} on the missing-row path so the
     * wall-clock time of "no such pat_id" is indistinguishable from
     * "row exists but wrong secret." Without this, an attacker can
     * probe pat_id existence via timing without knowing the secret.
     *
     * <p>The same hash is in
     * {@code spec/conformance/fixtures/identity/argon2id.json}
     * (verifies to "correcthorsebatterystaple"). Generated with the
     * spec floor parameters (m=19456, t=2, p=1). PAT secrets are
     * 43-char base64url strings (32 bytes); collision probability
     * with the dummy plaintext is vanishing.
     */
    public static final String DUMMY_PHC_HASH =
            "$argon2id$v=19$m=19456,t=2,p=1$"
                    + "779z4UHkLWR4w0TEo9gcHg$"
                    + "Gz0+nGnpokhsKi1cPlx8i74FBN1Nq0OURZ3xso1AHMU";

    private PatLimits() {
        // utility
    }
}
