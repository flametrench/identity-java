// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.time.Clock;

class InMemoryAuthGatesTest extends AuthGatesContract {
    @Override
    protected IdentityStore newStore(Clock clock) {
        return new InMemoryIdentityStore(clock);
    }
}
