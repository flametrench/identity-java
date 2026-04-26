// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/**
 * Base class for WebAuthn assertion verification errors.
 *
 * <p>Each subclass carries a stable {@code reason} token and the
 * OpenAPI-style {@code code} {@code "webauthn.<reason>"}.
 */
public class WebAuthnError extends IdentityError {
    private final String reason;

    public WebAuthnError(String message, String reason) {
        super(message, "webauthn." + reason);
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }
}
