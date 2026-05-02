# Changelog

All notable changes to `dev.flametrench:identity` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.3.0] — Unreleased (Maven Central publish blocked)

### Added (personal access tokens, ADR 0016)
- New `dev.flametrench.identity` records: `PersonalAccessToken`, `VerifiedPat`, `CreatePatResult`. New enum: `PatStatus`.
- New exceptions: `InvalidPatTokenError`, `PatExpiredError`, `PatRevokedError`. The "no row" and "wrong secret" cases conflate to `InvalidPatTokenError` to defend against a token-presence timing oracle (ADR 0016 §"Verification semantics").
- New methods on `IdentityStore` (implemented in both `InMemoryIdentityStore` and `PostgresIdentityStore`): `createPat`, `getPat`, `listPatsForUser`, `revokePat`, `verifyPatToken`.
- Wire format: `pat_<32hex-id>_<base64url-secret>` (Stripe-style id-then-secret). The plaintext token is returned ONCE in `createPat` and never again — the server stores only an Argon2id hash of the secret segment at the cred-password parameter floor.
- New `patLastUsedCoalesceSeconds` constructor option on both stores (default 60s) avoids a write-per-request hot path on the `last_used_at` column. 0 disables coalescing.
- `PostgresIdentityStore` PAT methods cooperate with caller-owned `Connection` via `SAVEPOINT/RELEASE` (ADR 0013).
- 32 new tests (20 `InMemory` + 12 `Pg`) using a controllable `TestClock` for deterministic last_used_at coalescing assertions.

### Required dependency bump
- `dev.flametrench:ids` constraint now `0.3.0` for the `pat` type prefix (ADR 0016).

### Release status
- Tagged in lockstep with the Node and PHP v0.3.0 cuts; Maven Central publication remains externally blocked. Local install via `mvn install -DskipTests` works for downstream consumers.

## [v0.2.0] — 2026-04-30

### Released
- v0.2 stable cutoff. No functional changes from `v0.2.0-rc.5` — same source, version bumped to drop the `-rc` suffix at the spec v0.2.0 freeze. The `ids` dependency was bumped from `0.2.0-rc.1` to `0.2.0` to track the family. Maven Central publication is gated on Sonatype Central Portal credential regeneration; until that unblocks, the `0.2.0` jar is built and validated locally (`mvn -P release verify -Dgpg.skip=true`).

## [v0.2.0-rc.5] — 2026-04-27

### Fixed (security posture)
- `verifyPassword` now consults `usr_mfa_policy` and returns `VerifiedCredential.mfaRequired() = true` when a user has `required = true` AND the grace window has elapsed (or was never set). Previously the policy table was decorative — the SDK never read it, so an adopter configuring per-user MFA enforcement could be bypassed by application code that called `createSession` directly without checking the policy. The new field is additive (defaults to `false`), so adopters who do not configure a policy see no behavioral change. Applications MUST gate `createSession` on `mfaRequired` by calling `verifyMfa` first when it is `true`. The `VerifiedCredential` record retains a 2-arg constructor for backwards compatibility. (ADR 0008.)

## [v0.2.0-rc.4] — 2026-04-27

### Added
- `dev.flametrench.identity.PostgresIdentityStore` — a Postgres-backed `IdentityStore`. Mirrors `InMemoryIdentityStore` byte-for-byte at the SDK boundary; the difference is durability and concurrency.
  - Schema: `spec/reference/postgres.sql` (the `usr`, `cred`, `ses`, `mfa`, `usr_mfa_policy` tables, plus `ses.mfa_verified_at`).
  - Connection: accepts a `javax.sql.DataSource`. `org.postgresql:postgresql:42.7.4` is declared `<optional>true</optional>` — adopters using only the in-memory store don't transitively pull in the JDBC driver.
  - Token storage: SHA-256 hashed and stored as 32 raw bytes (`BYTEA`). Plaintext tokens are returned ONCE on create/refresh and never persisted.
  - Multi-statement ops (`revokeUser` cascade, credential rotation, `refreshSession`, MFA confirm/verify, recovery-slot consumption) run inside a transaction.
  - Coverage: 23 integration tests, gated on `IDENTITY_POSTGRES_URL`.

## [v0.2.0-rc.3] — 2026-04-26

### Added (MFA store ops, ADR 0008 Phase 1)
- `enrollTotpFactor`, `enrollWebAuthnFactor`, `enrollRecoveryFactor`, `confirmTotpFactor`, `confirmWebAuthnFactor`, `revokeMfaFactor`, `verifyMfa`, `getMfaPolicy`, `setMfaPolicy` on `IdentityStore`. Wires the MFA primitives behind a single store-level surface so adopters don't write the orchestration themselves.

## [v0.2.0-rc.2] — 2026-04-26

WebAuthn RS256 + EdDSA assertion verification per ADR 0010.

## [v0.2.0-rc.1] — 2026-04-25

Initial v0.2 release-candidate.

For pre-rc history, see git tags.
