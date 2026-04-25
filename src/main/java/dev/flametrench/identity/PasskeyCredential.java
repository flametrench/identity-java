// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;

public record PasskeyCredential(
        String id,
        String usrId,
        String identifier,
        Status status,
        String replaces,
        int passkeySignCount,
        String passkeyRpId,
        Instant createdAt,
        Instant updatedAt
) implements Credential {
    @Override
    public CredentialType type() {
        return CredentialType.PASSKEY;
    }
}
