// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.util.List;

/** Success outcome of {@link IdentityStore#verifyPatToken} (ADR 0016). */
public record VerifiedPat(String patId, String usrId, List<String> scope) {}
