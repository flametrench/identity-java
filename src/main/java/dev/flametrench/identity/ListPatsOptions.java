// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

/** Pagination options for {@link IdentityStore#listPatsForUser}. */
public record ListPatsOptions(String cursor, int limit) {}
