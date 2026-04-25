// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;

public record OidcCredential(
        String id,
        String usrId,
        String identifier,
        Status status,
        String replaces,
        String oidcIssuer,
        String oidcSubject,
        Instant createdAt,
        Instant updatedAt
) implements Credential {
    @Override
    public CredentialType type() {
        return CredentialType.OIDC;
    }
}
