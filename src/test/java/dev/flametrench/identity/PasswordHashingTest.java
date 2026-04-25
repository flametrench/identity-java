// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordHashingTest {

    @Test
    void hashThenVerifyRoundTrip() {
        String phc = PasswordHashing.hash("correcthorsebatterystaple");
        assertTrue(phc.startsWith("$argon2id$"));
        assertTrue(PasswordHashing.verify(phc, "correcthorsebatterystaple"));
        assertFalse(PasswordHashing.verify(phc, "wrong"));
    }

    @Test
    void verifyReturnsFalseForGarbageInput() {
        assertFalse(PasswordHashing.verify("not a phc string", "anything"));
        assertFalse(PasswordHashing.verify("", ""));
        assertFalse(PasswordHashing.verify(null, "x"));
        assertFalse(PasswordHashing.verify("$argon2id$x", null));
    }
}
