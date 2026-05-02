// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.util.List;

/**
 * Successful result of {@link IdentityStore#verifyPatToken} (ADR 0016).
 *
 * <p>Carries only the fields a request-handling middleware needs to
 * populate audit + authz context: the pat id (audit handle), the
 * usrId (the principal the request acts as), and the scope (the
 * application-defined claims attached to this token).
 *
 * <p>The plaintext token is never returned here — by this point the
 * verifier has already discarded it.
 */
public record VerifiedPat(String patId, String usrId, List<String> scope) {}
