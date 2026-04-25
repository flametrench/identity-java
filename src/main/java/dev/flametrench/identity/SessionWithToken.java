// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Returned from {@code createSession} / {@code refreshSession}. The
 * bearer token is the only chance to capture it — implementations
 * persist only its SHA-256 hash.
 */
public record SessionWithToken(Session session, String token) {
}
