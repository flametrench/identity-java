// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Result of {@link IdentityStore#verifyPassword}.
 *
 * <p>{@code mfaRequired} is {@code true} when {@code usr_mfa_policy.required}
 * is true AND the grace window has elapsed (or was never set). Applications
 * MUST call {@link IdentityStore#verifyMfa} before {@link IdentityStore#createSession}
 * when this is true. Defaults to {@code false} for adopters who never enable
 * a policy. (ADR 0008.)
 */
public record VerifiedCredential(String usrId, String credId, boolean mfaRequired) {

    /** Convenience constructor for the no-policy / no-MFA case. */
    public VerifiedCredential(String usrId, String credId) {
        this(usrId, credId, false);
    }
}
