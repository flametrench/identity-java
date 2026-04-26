// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Sealed marker for an MFA verification proof. Stores switch on the
 * concrete subtype to dispatch.
 */
public sealed interface MfaProof permits TotpProof, WebAuthnProof, RecoveryProof {}
