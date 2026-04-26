// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Successful WebAuthn assertion verification result.
 *
 * <p>The new sign count MUST be persisted atomically with the session
 * decision; otherwise a race lets a cloned authenticator slip through.
 */
public record WebAuthnAssertionResult(long newSignCount) {}
