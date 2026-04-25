// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Instant;

/**
 * Sealed marker for the three credential variants in v0.1. Use pattern
 * matching to narrow to a concrete type, or check {@link #type()}.
 *
 * <p>Sensitive material — password hashes and passkey public keys — is
 * intentionally NOT part of any public Credential record. The
 * IdentityStore stores those internally; verification operations are
 * the only way to compare.
 */
public sealed interface Credential
        permits PasswordCredential, PasskeyCredential, OidcCredential {

    String id();

    String usrId();

    CredentialType type();

    String identifier();

    Status status();

    String replaces();

    Instant createdAt();

    Instant updatedAt();
}
