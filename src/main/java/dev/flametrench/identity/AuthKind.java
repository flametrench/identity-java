// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import java.util.regex.Pattern;

/**
 * Bearer-type classifier and PAT structural validator per ADR 0016.
 *
 * <p>{@link #classifyBearer} is a pure prefix classifier — no DB hit.
 * {@link #isStructurallyValidPatToken} validates the full PAT wire format
 * without any secret verification.
 */
public final class AuthKind {

    public static final String PAT     = "pat";
    public static final String SHARE   = "share";
    public static final String SESSION = "session";
    public static final String SYSTEM  = "system";

    /** Canonical dummy PHC hash for timing-oracle defence on missing-row path (ADR 0016 / security-audit-v0.3.md H2). */
    public static final String PAT_DUMMY_PHC_HASH =
            "$argon2id$v=19$m=19456,t=2,p=1$779z4UHkLWR4w0TEo9gcHg$Gz0+nGnpokhsKi1cPlx8i74FBN1Nq0OURZ3xso1AHMU";

    /** Maximum secret segment length before Argon2id is invoked (ADR 0016 / security-audit-v0.3.md H6). */
    public static final int PAT_MAX_SECRET_LENGTH = 256;

    /** pat_<32hex>_<base64url-secret> */
    private static final Pattern PAT_WIRE_FORMAT =
            Pattern.compile("^pat_[0-9a-f]{32}_[A-Za-z0-9_-]+$");

    private AuthKind() {}

    /**
     * Classify a bearer token by prefix per ADR 0016 §"Bearer routing".
     * Returns one of {@link #PAT}, {@link #SHARE}, or {@link #SESSION}.
     */
    public static String classifyBearer(String token) {
        if (token != null && token.startsWith("pat_")) return PAT;
        if (token != null && token.startsWith("shr_")) return SHARE;
        return SESSION;
    }

    /**
     * Structural check for PAT bearer format per ADR 0016 §"Wire format".
     * Returns {@code true} iff token matches {@code pat_<32hex>_<base64url>}.
     * Does NOT hit the database or Argon2id verifier.
     */
    public static boolean isStructurallyValidPatToken(String token) {
        if (token == null) return false;
        return PAT_WIRE_FORMAT.matcher(token).matches();
    }
}
