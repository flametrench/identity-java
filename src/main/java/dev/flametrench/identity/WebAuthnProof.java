// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Inputs for verifying a WebAuthn assertion against a stored factor.
 *
 * <p>{@code credentialId} matches the {@code identifier} field on the
 * WebAuthn factor (base64url-encoded WebAuthn credential ID). The store
 * uses it to locate the factor; the assertion bytes are verified
 * against the stored COSE public key.
 *
 * <p>{@code expectedChallenge} is the raw bytes of the challenge the
 * application issued for this assertion attempt — challenge issuance
 * is the host application's responsibility, not the SDK's.
 */
public record WebAuthnProof(
        String credentialId,
        byte[] authenticatorData,
        byte[] clientDataJson,
        byte[] signature,
        byte[] expectedChallenge,
        String expectedOrigin
) implements MfaProof {}
