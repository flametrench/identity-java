// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

public class AlreadyTerminalError extends IdentityError {
    public AlreadyTerminalError(String message) {
        super(message, "already_terminal");
    }
}
