// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import dev.flametrench.ids.Id;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * PostgresIdentityStore — Postgres-backed implementation of IdentityStore.
 *
 * <p>Mirrors {@link InMemoryIdentityStore} byte-for-byte at the SDK
 * boundary; the difference is durability and concurrency. Schema lives
 * in {@code spec/reference/postgres.sql}.
 *
 * <p>Bearer tokens are SHA-256 hashed and stored as 32 raw bytes
 * (BYTEA). Plaintext tokens are returned ONCE on create/refresh and
 * never persisted.
 *
 * <p>Multi-statement ops (revokeUser cascade, rotation, refreshSession,
 * MFA confirm/verify) run inside a transaction so state transitions
 * are atomic.
 */
public class PostgresIdentityStore implements IdentityStore {

    /** Pending TOTP/WebAuthn factor TTL per ADR 0008. */
    public static final long PENDING_FACTOR_TTL_SECONDS = 600L;

    private static final String UNIQUE_VIOLATION = "23505";

    private static final String CRED_COLS =
            "id, usr_id, type, identifier, status, replaces, password_hash, "
            + "passkey_public_key, passkey_sign_count, passkey_rp_id, "
            + "oidc_issuer, oidc_subject, created_at, updated_at";

    private static final String SES_COLS =
            "id, usr_id, cred_id, created_at, expires_at, revoked_at, token_hash, mfa_verified_at";

    private static final String MFA_COLS =
            "id, usr_id, type, status, replaces, identifier, "
            + "totp_secret, totp_algorithm, totp_digits, totp_period, "
            + "webauthn_public_key, webauthn_sign_count, webauthn_rp_id, "
            + "webauthn_aaguid, webauthn_transports, "
            + "recovery_hashes, recovery_consumed, pending_expires_at, "
            + "created_at, updated_at";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final DataSource dataSource;
    private final Clock clock;

    public PostgresIdentityStore(DataSource dataSource) {
        this(dataSource, Clock.systemUTC());
    }

    public PostgresIdentityStore(DataSource dataSource, Clock clock) {
        this.dataSource = dataSource;
        this.clock = clock;
    }

    private Instant now() {
        return clock.instant();
    }

    private static UUID wireToUuid(String wireId) {
        return UUID.fromString(Id.decode(wireId).uuid());
    }

    private static boolean isUniqueViolation(SQLException e) {
        return UNIQUE_VIOLATION.equals(e.getSQLState());
    }

    private static byte[] hashTokenBytes(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(token.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String generateToken() {
        byte[] raw = new byte[32];
        SECURE_RANDOM.nextBytes(raw);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    @FunctionalInterface
    private interface TxFn<T> {
        T apply(Connection conn) throws SQLException;
    }

    private <T> T tx(TxFn<T> fn) {
        try (Connection conn = dataSource.getConnection()) {
            boolean prevAuto = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try {
                T result = fn.apply(conn);
                conn.commit();
                return result;
            } catch (SQLException | RuntimeException e) {
                try {
                    conn.rollback();
                } catch (SQLException ignored) {
                }
                if (e instanceof SQLException) throw new RuntimeException(e);
                throw (RuntimeException) e;
            } finally {
                conn.setAutoCommit(prevAuto);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    // ─── Row mappers ───

    private static User rowToUser(ResultSet rs) throws SQLException {
        return new User(
                Id.encode("usr", rs.getString("id")),
                Status.valueOf(rs.getString("status").toUpperCase()),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at").toInstant()
        );
    }

    private static Credential rowToCred(ResultSet rs) throws SQLException {
        String credId = Id.encode("cred", rs.getString("id"));
        String usrId = Id.encode("usr", rs.getString("usr_id"));
        String type = rs.getString("type");
        String identifier = rs.getString("identifier");
        Status status = Status.valueOf(rs.getString("status").toUpperCase());
        String replacesUuid = rs.getString("replaces");
        String replaces = replacesUuid != null ? Id.encode("cred", replacesUuid) : null;
        Instant createdAt = rs.getTimestamp("created_at").toInstant();
        Instant updatedAt = rs.getTimestamp("updated_at").toInstant();
        return switch (type) {
            case "password" -> new PasswordCredential(
                    credId, usrId, identifier, status, replaces, createdAt, updatedAt
            );
            case "passkey" -> new PasskeyCredential(
                    credId, usrId, identifier, status, replaces,
                    rs.getInt("passkey_sign_count"),
                    rs.getString("passkey_rp_id"),
                    createdAt, updatedAt
            );
            default -> new OidcCredential(
                    credId, usrId, identifier, status, replaces,
                    rs.getString("oidc_issuer"),
                    rs.getString("oidc_subject"),
                    createdAt, updatedAt
            );
        };
    }

    private static Session rowToSession(ResultSet rs) throws SQLException {
        Timestamp revokedAt = rs.getTimestamp("revoked_at");
        return new Session(
                Id.encode("ses", rs.getString("id")),
                Id.encode("usr", rs.getString("usr_id")),
                Id.encode("cred", rs.getString("cred_id")),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("expires_at").toInstant(),
                revokedAt != null ? revokedAt.toInstant() : null
        );
    }

    private static Factor rowToFactor(ResultSet rs) throws SQLException {
        String factorId = Id.encode("mfa", rs.getString("id"));
        String usrId = Id.encode("usr", rs.getString("usr_id"));
        String type = rs.getString("type");
        FactorStatus status = FactorStatus.valueOf(rs.getString("status").toUpperCase());
        String replacesUuid = rs.getString("replaces");
        String replaces = replacesUuid != null ? Id.encode("mfa", replacesUuid) : null;
        Instant createdAt = rs.getTimestamp("created_at").toInstant();
        Instant updatedAt = rs.getTimestamp("updated_at").toInstant();
        return switch (type) {
            case "totp" -> new TotpFactor(
                    factorId, usrId, rs.getString("identifier"),
                    status, replaces, createdAt, updatedAt
            );
            case "webauthn" -> new WebAuthnFactor(
                    factorId, usrId, rs.getString("identifier"),
                    status, replaces,
                    rs.getString("webauthn_rp_id"),
                    rs.getLong("webauthn_sign_count"),
                    createdAt, updatedAt
            );
            default -> {
                Array consumed = rs.getArray("recovery_consumed");
                int remaining = 0;
                if (consumed != null) {
                    Object[] arr = (Object[]) consumed.getArray();
                    for (Object v : arr) {
                        if (Boolean.FALSE.equals(v)) remaining++;
                    }
                }
                yield new RecoveryFactor(
                        factorId, usrId, status, replaces,
                        createdAt, updatedAt, remaining
                );
            }
        };
    }

    private static UserMfaPolicy rowToPolicy(ResultSet rs) throws SQLException {
        Timestamp grace = rs.getTimestamp("grace_until");
        return new UserMfaPolicy(
                Id.encode("usr", rs.getString("usr_id")),
                rs.getBoolean("required"),
                grace != null ? grace.toInstant() : null,
                rs.getTimestamp("updated_at").toInstant()
        );
    }

    // ─── Users ───

    @Override
    public User createUser() {
        UUID usrUuid = UUID.fromString(Id.decode(Id.generate("usr")).uuid());
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "INSERT INTO usr (id) VALUES (?)"
                   + " RETURNING id, status, created_at, updated_at")) {
            ps.setObject(1, usrUuid);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rowToUser(rs);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public User getUser(String usrId) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT id, status, created_at, updated_at FROM usr WHERE id = ?")) {
            ps.setObject(1, wireToUuid(usrId));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new NotFoundError("User " + usrId + " not found");
                return rowToUser(rs);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public User suspendUser(String usrId) {
        return tx(conn -> {
            UUID uuid = wireToUuid(usrId);
            String currentStatus;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT status FROM usr WHERE id = ? FOR UPDATE")) {
                ps.setObject(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) throw new NotFoundError("User " + usrId + " not found");
                    currentStatus = rs.getString("status");
                }
            }
            if ("revoked".equals(currentStatus)) {
                throw new AlreadyTerminalError("User " + usrId + " is revoked");
            }
            if ("suspended".equals(currentStatus)) {
                return getUser(usrId);
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE usr SET status = 'suspended' WHERE id = ?"
                  + " RETURNING id, status, created_at, updated_at")) {
                ps.setObject(1, uuid);
                User updated;
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    updated = rowToUser(rs);
                }
                try (PreparedStatement ps2 = conn.prepareStatement(
                        "UPDATE ses SET revoked_at = ? WHERE usr_id = ? AND revoked_at IS NULL")) {
                    ps2.setTimestamp(1, Timestamp.from(now()));
                    ps2.setObject(2, uuid);
                    ps2.executeUpdate();
                }
                return updated;
            }
        });
    }

    @Override
    public User reinstateUser(String usrId) {
        return tx(conn -> {
            UUID uuid = wireToUuid(usrId);
            String status;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT status FROM usr WHERE id = ? FOR UPDATE")) {
                ps.setObject(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) throw new NotFoundError("User " + usrId + " not found");
                    status = rs.getString("status");
                }
            }
            if (!"suspended".equals(status)) {
                throw new PreconditionError(
                        "User " + usrId + " is " + status + "; only suspended users can be reinstated",
                        "invalid_transition"
                );
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE usr SET status = 'active' WHERE id = ?"
                  + " RETURNING id, status, created_at, updated_at")) {
                ps.setObject(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return rowToUser(rs);
                }
            }
        });
    }

    @Override
    public User revokeUser(String usrId) {
        return tx(conn -> {
            UUID uuid = wireToUuid(usrId);
            String status;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT status FROM usr WHERE id = ? FOR UPDATE")) {
                ps.setObject(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) throw new NotFoundError("User " + usrId + " not found");
                    status = rs.getString("status");
                }
            }
            if ("revoked".equals(status)) {
                throw new AlreadyTerminalError("User " + usrId + " is already revoked");
            }
            Timestamp ts = Timestamp.from(now());
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE cred SET status = 'revoked' WHERE usr_id = ? AND status = 'active'")) {
                ps.setObject(1, uuid);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE ses SET revoked_at = ? WHERE usr_id = ? AND revoked_at IS NULL")) {
                ps.setTimestamp(1, ts);
                ps.setObject(2, uuid);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE usr SET status = 'revoked' WHERE id = ?"
                  + " RETURNING id, status, created_at, updated_at")) {
                ps.setObject(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return rowToUser(rs);
                }
            }
        });
    }

    // ─── Credentials ───

    private UUID ensureUserActive(Connection conn, String usrId) throws SQLException {
        UUID uuid = wireToUuid(usrId);
        try (PreparedStatement ps = conn.prepareStatement("SELECT status FROM usr WHERE id = ?")) {
            ps.setObject(1, uuid);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new NotFoundError("User " + usrId + " not found");
                String status = rs.getString("status");
                if (!"active".equals(status)) {
                    throw new PreconditionError(
                            "Cannot create credentials for " + status + " user",
                            "user_not_active"
                    );
                }
            }
        }
        return uuid;
    }

    @Override
    public PasswordCredential createPasswordCredential(
            String usrId, String identifier, String password
    ) {
        try (Connection conn = dataSource.getConnection()) {
            UUID userUuid = ensureUserActive(conn, usrId);
            UUID credUuid = UUID.fromString(Id.decode(Id.generate("cred")).uuid());
            String hash = PasswordHashing.hash(password);
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO cred (id, usr_id, type, identifier, password_hash)"
                  + " VALUES (?, ?, 'password', ?, ?) RETURNING " + CRED_COLS)) {
                ps.setObject(1, credUuid);
                ps.setObject(2, userUuid);
                ps.setString(3, identifier);
                ps.setString(4, hash);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return (PasswordCredential) rowToCred(rs);
                }
            }
        } catch (SQLException e) {
            if (isUniqueViolation(e)) {
                throw new DuplicateCredentialError(
                        "An active password credential already exists for identifier " + identifier
                );
            }
            throw new RuntimeException(e);
        }
    }

    @Override
    public PasskeyCredential createPasskeyCredential(
            String usrId, String identifier, byte[] publicKey, int signCount, String rpId
    ) {
        try (Connection conn = dataSource.getConnection()) {
            UUID userUuid = ensureUserActive(conn, usrId);
            UUID credUuid = UUID.fromString(Id.decode(Id.generate("cred")).uuid());
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO cred (id, usr_id, type, identifier,"
                  + " passkey_public_key, passkey_sign_count, passkey_rp_id)"
                  + " VALUES (?, ?, 'passkey', ?, ?, ?, ?) RETURNING " + CRED_COLS)) {
                ps.setObject(1, credUuid);
                ps.setObject(2, userUuid);
                ps.setString(3, identifier);
                ps.setBytes(4, publicKey);
                ps.setInt(5, signCount);
                ps.setString(6, rpId);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return (PasskeyCredential) rowToCred(rs);
                }
            }
        } catch (SQLException e) {
            if (isUniqueViolation(e)) {
                throw new DuplicateCredentialError(
                        "An active passkey credential already exists for identifier " + identifier
                );
            }
            throw new RuntimeException(e);
        }
    }

    @Override
    public OidcCredential createOidcCredential(
            String usrId, String identifier, String oidcIssuer, String oidcSubject
    ) {
        try (Connection conn = dataSource.getConnection()) {
            UUID userUuid = ensureUserActive(conn, usrId);
            UUID credUuid = UUID.fromString(Id.decode(Id.generate("cred")).uuid());
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO cred (id, usr_id, type, identifier, oidc_issuer, oidc_subject)"
                  + " VALUES (?, ?, 'oidc', ?, ?, ?) RETURNING " + CRED_COLS)) {
                ps.setObject(1, credUuid);
                ps.setObject(2, userUuid);
                ps.setString(3, identifier);
                ps.setString(4, oidcIssuer);
                ps.setString(5, oidcSubject);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return (OidcCredential) rowToCred(rs);
                }
            }
        } catch (SQLException e) {
            if (isUniqueViolation(e)) {
                throw new DuplicateCredentialError(
                        "An active oidc credential already exists for identifier " + identifier
                );
            }
            throw new RuntimeException(e);
        }
    }

    @Override
    public Credential getCredential(String credId) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT " + CRED_COLS + " FROM cred WHERE id = ?")) {
            ps.setObject(1, wireToUuid(credId));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new NotFoundError("Credential " + credId + " not found");
                return rowToCred(rs);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public List<Credential> listCredentialsForUser(String usrId) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT " + CRED_COLS + " FROM cred WHERE usr_id = ? ORDER BY created_at")) {
            ps.setObject(1, wireToUuid(usrId));
            try (ResultSet rs = ps.executeQuery()) {
                List<Credential> rows = new ArrayList<>();
                while (rs.next()) rows.add(rowToCred(rs));
                return List.copyOf(rows);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Credential findCredentialByIdentifier(CredentialType type, String identifier) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT " + CRED_COLS + " FROM cred"
                   + " WHERE type = ? AND identifier = ? AND status = 'active'")) {
            ps.setString(1, type.getValue());
            ps.setString(2, identifier);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                return rowToCred(rs);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private static class CredRowDirect {
        UUID id;
        UUID usrId;
        String type;
        String identifier;
        String status;
    }

    private CredRowDirect lockCredForRotation(
            Connection conn, String credId, CredentialType expected
    ) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, usr_id, type, identifier, status FROM cred WHERE id = ? FOR UPDATE")) {
            ps.setObject(1, wireToUuid(credId));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new NotFoundError("Credential " + credId + " not found");
                CredRowDirect r = new CredRowDirect();
                r.id = (UUID) rs.getObject("id");
                r.usrId = (UUID) rs.getObject("usr_id");
                r.type = rs.getString("type");
                r.identifier = rs.getString("identifier");
                r.status = rs.getString("status");
                if (!"active".equals(r.status)) {
                    throw new CredentialNotActiveError("Credential " + credId + " is " + r.status);
                }
                if (!r.type.equals(expected.getValue())) {
                    throw new CredentialTypeMismatchError(
                            "Cannot rotate " + r.type + " credential with " + expected.getValue() + " payload"
                    );
                }
                return r;
            }
        }
    }

    private void revokeOldOnRotation(Connection conn, UUID oldId, Timestamp ts) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE cred SET status = 'revoked' WHERE id = ?")) {
            ps.setObject(1, oldId);
            ps.executeUpdate();
        }
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE ses SET revoked_at = ? WHERE cred_id = ? AND revoked_at IS NULL")) {
            ps.setTimestamp(1, ts);
            ps.setObject(2, oldId);
            ps.executeUpdate();
        }
    }

    @Override
    public PasswordCredential rotatePassword(String credId, String newPassword) {
        return tx(conn -> {
            CredRowDirect old = lockCredForRotation(conn, credId, CredentialType.PASSWORD);
            Timestamp ts = Timestamp.from(now());
            revokeOldOnRotation(conn, old.id, ts);
            UUID newId = UUID.fromString(Id.decode(Id.generate("cred")).uuid());
            String hash = PasswordHashing.hash(newPassword);
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO cred (id, usr_id, type, identifier, password_hash, replaces)"
                  + " VALUES (?, ?, 'password', ?, ?, ?) RETURNING " + CRED_COLS)) {
                ps.setObject(1, newId);
                ps.setObject(2, old.usrId);
                ps.setString(3, old.identifier);
                ps.setString(4, hash);
                ps.setObject(5, old.id);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return (PasswordCredential) rowToCred(rs);
                }
            }
        });
    }

    @Override
    public PasskeyCredential rotatePasskey(
            String credId, byte[] publicKey, int signCount, String rpId
    ) {
        return tx(conn -> {
            CredRowDirect old = lockCredForRotation(conn, credId, CredentialType.PASSKEY);
            Timestamp ts = Timestamp.from(now());
            revokeOldOnRotation(conn, old.id, ts);
            UUID newId = UUID.fromString(Id.decode(Id.generate("cred")).uuid());
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO cred (id, usr_id, type, identifier,"
                  + " passkey_public_key, passkey_sign_count, passkey_rp_id, replaces)"
                  + " VALUES (?, ?, 'passkey', ?, ?, ?, ?, ?) RETURNING " + CRED_COLS)) {
                ps.setObject(1, newId);
                ps.setObject(2, old.usrId);
                ps.setString(3, old.identifier);
                ps.setBytes(4, publicKey);
                ps.setInt(5, signCount);
                ps.setString(6, rpId);
                ps.setObject(7, old.id);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return (PasskeyCredential) rowToCred(rs);
                }
            }
        });
    }

    @Override
    public OidcCredential rotateOidc(String credId, String oidcIssuer, String oidcSubject) {
        return tx(conn -> {
            CredRowDirect old = lockCredForRotation(conn, credId, CredentialType.OIDC);
            Timestamp ts = Timestamp.from(now());
            revokeOldOnRotation(conn, old.id, ts);
            UUID newId = UUID.fromString(Id.decode(Id.generate("cred")).uuid());
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO cred (id, usr_id, type, identifier, oidc_issuer, oidc_subject, replaces)"
                  + " VALUES (?, ?, 'oidc', ?, ?, ?, ?) RETURNING " + CRED_COLS)) {
                ps.setObject(1, newId);
                ps.setObject(2, old.usrId);
                ps.setString(3, old.identifier);
                ps.setString(4, oidcIssuer);
                ps.setString(5, oidcSubject);
                ps.setObject(6, old.id);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return (OidcCredential) rowToCred(rs);
                }
            }
        });
    }

    @Override
    public Credential suspendCredential(String credId) {
        return tx(conn -> {
            UUID uuid = wireToUuid(credId);
            String status;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT status FROM cred WHERE id = ? FOR UPDATE")) {
                ps.setObject(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) throw new NotFoundError("Credential " + credId + " not found");
                    status = rs.getString("status");
                }
            }
            if (!"active".equals(status)) {
                throw new PreconditionError(
                        "Credential " + credId + " is " + status + "; only active credentials can be suspended",
                        "cred_not_active"
                );
            }
            Timestamp ts = Timestamp.from(now());
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE cred SET status = 'suspended' WHERE id = ? RETURNING " + CRED_COLS)) {
                ps.setObject(1, uuid);
                Credential updated;
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    updated = rowToCred(rs);
                }
                try (PreparedStatement ps2 = conn.prepareStatement(
                        "UPDATE ses SET revoked_at = ? WHERE cred_id = ? AND revoked_at IS NULL")) {
                    ps2.setTimestamp(1, ts);
                    ps2.setObject(2, uuid);
                    ps2.executeUpdate();
                }
                return updated;
            }
        });
    }

    @Override
    public Credential reinstateCredential(String credId) {
        return tx(conn -> {
            UUID uuid = wireToUuid(credId);
            String status;
            String credType;
            String identifier;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT status, type, identifier FROM cred WHERE id = ? FOR UPDATE")) {
                ps.setObject(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) throw new NotFoundError("Credential " + credId + " not found");
                    status = rs.getString("status");
                    credType = rs.getString("type");
                    identifier = rs.getString("identifier");
                }
            }
            if (!"suspended".equals(status)) {
                throw new PreconditionError(
                        "Credential " + credId + " is " + status + "; only suspended credentials can be reinstated",
                        "invalid_transition"
                );
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE cred SET status = 'active' WHERE id = ? RETURNING " + CRED_COLS)) {
                ps.setObject(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return rowToCred(rs);
                }
            } catch (SQLException e) {
                if (isUniqueViolation(e)) {
                    throw new DuplicateCredentialError(
                            "Another active " + credType + " credential already exists for "
                          + identifier + "; cannot reinstate"
                    );
                }
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public Credential revokeCredential(String credId) {
        return tx(conn -> {
            UUID uuid = wireToUuid(credId);
            String status;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT status FROM cred WHERE id = ? FOR UPDATE")) {
                ps.setObject(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) throw new NotFoundError("Credential " + credId + " not found");
                    status = rs.getString("status");
                }
            }
            if ("revoked".equals(status)) {
                throw new AlreadyTerminalError("Credential " + credId + " is already revoked");
            }
            Timestamp ts = Timestamp.from(now());
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE cred SET status = 'revoked' WHERE id = ? RETURNING " + CRED_COLS)) {
                ps.setObject(1, uuid);
                Credential updated;
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    updated = rowToCred(rs);
                }
                try (PreparedStatement ps2 = conn.prepareStatement(
                        "UPDATE ses SET revoked_at = ? WHERE cred_id = ? AND revoked_at IS NULL")) {
                    ps2.setTimestamp(1, ts);
                    ps2.setObject(2, uuid);
                    ps2.executeUpdate();
                }
                return updated;
            }
        });
    }

    @Override
    public VerifiedCredential verifyPassword(String identifier, String password) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT id, usr_id, password_hash FROM cred"
                   + " WHERE type = 'password' AND identifier = ? AND status = 'active'")) {
            ps.setString(1, identifier);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new InvalidCredentialError("Invalid credential");
                String hash = rs.getString("password_hash");
                if (hash == null || !PasswordHashing.verify(hash, password)) {
                    throw new InvalidCredentialError("Invalid credential");
                }
                String usrUuid = rs.getString("usr_id");
                String credUuid = rs.getString("id");
                // ADR 0008: surface usr_mfa_policy state. Apps MUST gate
                // createSession on mfaRequired by calling verifyMfa first
                // when true.
                boolean mfaRequired = false;
                try (PreparedStatement polPs = conn.prepareStatement(
                        "SELECT required, grace_until FROM usr_mfa_policy WHERE usr_id = ?")) {
                    polPs.setObject(1, java.util.UUID.fromString(usrUuid));
                    try (ResultSet polRs = polPs.executeQuery()) {
                        if (polRs.next() && polRs.getBoolean("required")) {
                            java.sql.Timestamp grace = polRs.getTimestamp("grace_until");
                            if (grace == null || !grace.toInstant().isAfter(clock.instant())) {
                                mfaRequired = true;
                            }
                        }
                    }
                }
                return new VerifiedCredential(
                        Id.encode("usr", usrUuid),
                        Id.encode("cred", credUuid),
                        mfaRequired
                );
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    // ─── Sessions ───

    @Override
    public SessionWithToken createSession(String usrId, String credId, long ttlSeconds) {
        if (ttlSeconds < 60) {
            throw new PreconditionError("ttlSeconds must be >= 60", "ttl_too_short");
        }
        return tx(conn -> {
            UUID userUuid = wireToUuid(usrId);
            UUID credUuid = wireToUuid(credId);
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT status FROM usr WHERE id = ?")) {
                ps.setObject(1, userUuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) throw new NotFoundError("User " + usrId + " not found");
                    if (!"active".equals(rs.getString("status"))) {
                        throw new PreconditionError(
                                "Cannot create session for " + rs.getString("status") + " user",
                                "user_not_active"
                        );
                    }
                }
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT status, usr_id FROM cred WHERE id = ?")) {
                ps.setObject(1, credUuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) throw new NotFoundError("Credential " + credId + " not found");
                    String credStatus = rs.getString("status");
                    if (!"active".equals(credStatus)) {
                        throw new CredentialNotActiveError("Credential " + credId + " is " + credStatus);
                    }
                    UUID credUsr = (UUID) rs.getObject("usr_id");
                    if (!credUsr.equals(userUuid)) {
                        throw new PreconditionError(
                                "Credential " + credId + " does not belong to " + usrId,
                                "cred_user_mismatch"
                        );
                    }
                }
            }
            Instant now = now();
            Instant expiresAt = now.plusSeconds(ttlSeconds);
            UUID sesUuid = UUID.fromString(Id.decode(Id.generate("ses")).uuid());
            String token = generateToken();
            byte[] tokenHash = hashTokenBytes(token);
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO ses (id, usr_id, cred_id, created_at, expires_at, token_hash)"
                  + " VALUES (?, ?, ?, ?, ?, ?) RETURNING " + SES_COLS)) {
                ps.setObject(1, sesUuid);
                ps.setObject(2, userUuid);
                ps.setObject(3, credUuid);
                ps.setTimestamp(4, Timestamp.from(now));
                ps.setTimestamp(5, Timestamp.from(expiresAt));
                ps.setBytes(6, tokenHash);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return new SessionWithToken(rowToSession(rs), token);
                }
            }
        });
    }

    @Override
    public Session getSession(String sesId) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT " + SES_COLS + " FROM ses WHERE id = ?")) {
            ps.setObject(1, wireToUuid(sesId));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new NotFoundError("Session " + sesId + " not found");
                return rowToSession(rs);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Page<Session> listSessionsForUser(String usrId, String cursor, int limit) {
        int cap = Math.min(limit, 200);
        StringBuilder sql = new StringBuilder(
                "SELECT " + SES_COLS + " FROM ses WHERE usr_id = ?"
        );
        if (cursor != null) sql.append(" AND id > ?");
        sql.append(" ORDER BY id LIMIT ?");
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql.toString())) {
            int idx = 1;
            ps.setObject(idx++, wireToUuid(usrId));
            if (cursor != null) ps.setObject(idx++, wireToUuid(cursor));
            ps.setInt(idx, cap + 1);
            try (ResultSet rs = ps.executeQuery()) {
                List<Session> rows = new ArrayList<>();
                while (rs.next()) rows.add(rowToSession(rs));
                boolean hasMore = rows.size() > cap;
                List<Session> data = hasMore ? rows.subList(0, cap) : rows;
                String next = hasMore && !data.isEmpty() ? data.get(data.size() - 1).id() : null;
                return new Page<>(List.copyOf(data), next);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Session verifySessionToken(String token) {
        byte[] tokenHash = hashTokenBytes(token);
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT " + SES_COLS + " FROM ses WHERE token_hash = ?")) {
            ps.setBytes(1, tokenHash);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new InvalidTokenError("Invalid token");
                byte[] stored = rs.getBytes("token_hash");
                if (!constantTimeEquals(stored, tokenHash)) {
                    throw new InvalidTokenError("Invalid token");
                }
                Timestamp revokedAt = rs.getTimestamp("revoked_at");
                if (revokedAt != null) {
                    throw new SessionExpiredError("Session is revoked");
                }
                Instant expiresAt = rs.getTimestamp("expires_at").toInstant();
                if (now().isAfter(expiresAt)) {
                    throw new SessionExpiredError("Session has expired");
                }
                return rowToSession(rs);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public SessionWithToken refreshSession(String sesId) {
        return tx(conn -> {
            UUID uuid = wireToUuid(sesId);
            UUID userUuid;
            UUID credUuid;
            Instant createdAt;
            Instant expiresAt;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT usr_id, cred_id, created_at, expires_at, revoked_at"
                  + " FROM ses WHERE id = ? FOR UPDATE")) {
                ps.setObject(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) throw new NotFoundError("Session " + sesId + " not found");
                    if (rs.getTimestamp("revoked_at") != null) {
                        throw new SessionExpiredError("Session is already revoked");
                    }
                    userUuid = (UUID) rs.getObject("usr_id");
                    credUuid = (UUID) rs.getObject("cred_id");
                    createdAt = rs.getTimestamp("created_at").toInstant();
                    expiresAt = rs.getTimestamp("expires_at").toInstant();
                }
            }
            Instant now = now();
            if (now.isAfter(expiresAt)) {
                throw new SessionExpiredError("Session has expired");
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE ses SET revoked_at = ? WHERE id = ?")) {
                ps.setTimestamp(1, Timestamp.from(now));
                ps.setObject(2, uuid);
                ps.executeUpdate();
            }
            long ttlSec = expiresAt.getEpochSecond() - createdAt.getEpochSecond();
            UUID newId = UUID.fromString(Id.decode(Id.generate("ses")).uuid());
            String token = generateToken();
            byte[] tokenHash = hashTokenBytes(token);
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO ses (id, usr_id, cred_id, created_at, expires_at, token_hash)"
                  + " VALUES (?, ?, ?, ?, ?, ?) RETURNING " + SES_COLS)) {
                ps.setObject(1, newId);
                ps.setObject(2, userUuid);
                ps.setObject(3, credUuid);
                ps.setTimestamp(4, Timestamp.from(now));
                ps.setTimestamp(5, Timestamp.from(now.plusSeconds(ttlSec)));
                ps.setBytes(6, tokenHash);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return new SessionWithToken(rowToSession(rs), token);
                }
            }
        });
    }

    @Override
    public Session revokeSession(String sesId) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "UPDATE ses SET revoked_at = COALESCE(revoked_at, ?)"
                   + " WHERE id = ? RETURNING " + SES_COLS)) {
            ps.setTimestamp(1, Timestamp.from(now()));
            ps.setObject(2, wireToUuid(sesId));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new NotFoundError("Session " + sesId + " not found");
                return rowToSession(rs);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    // ─── MFA ───

    private UUID requireUserActiveForMfa(Connection conn, String usrId) throws SQLException {
        UUID uuid = wireToUuid(usrId);
        try (PreparedStatement ps = conn.prepareStatement("SELECT status FROM usr WHERE id = ?")) {
            ps.setObject(1, uuid);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new NotFoundError("User " + usrId + " not found");
                String status = rs.getString("status");
                if (!"active".equals(status)) {
                    throw new PreconditionError(
                            "User " + usrId + " is " + status + "; cannot enroll MFA",
                            "user_not_active"
                    );
                }
            }
        }
        return uuid;
    }

    @Override
    public TotpEnrollmentResult enrollTotpFactor(String usrId, String identifier) {
        try (Connection conn = dataSource.getConnection()) {
            UUID userUuid = requireUserActiveForMfa(conn, usrId);
            // Partial-unique index `mfa_unique_active_singleton` only fires
            // on status='active'; new TOTP factors are inserted as 'pending',
            // so the duplicate-active check is explicit.
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT 1 FROM mfa WHERE usr_id = ? AND type = 'totp' AND status = 'active'")) {
                ps.setObject(1, userUuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        throw new PreconditionError(
                                "User " + usrId + " already has an active totp factor; revoke before re-enrolling",
                                "active_singleton_exists"
                        );
                    }
                }
            }
            Instant now = now();
            byte[] secret = Totp.generateSecret();
            UUID mfaUuid = UUID.fromString(Id.decode(Id.generate("mfa")).uuid());
            Instant expiresAt = now.plusSeconds(PENDING_FACTOR_TTL_SECONDS);
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO mfa (id, usr_id, type, status, identifier,"
                  + " totp_secret, totp_algorithm, totp_digits, totp_period,"
                  + " pending_expires_at, created_at, updated_at)"
                  + " VALUES (?, ?, 'totp', 'pending', ?, ?, ?, ?, ?, ?, ?, ?)"
                  + " RETURNING " + MFA_COLS)) {
                ps.setObject(1, mfaUuid);
                ps.setObject(2, userUuid);
                ps.setString(3, identifier);
                ps.setBytes(4, secret);
                ps.setString(5, Totp.DEFAULT_ALGORITHM);
                ps.setInt(6, Totp.DEFAULT_DIGITS);
                ps.setInt(7, Totp.DEFAULT_PERIOD);
                ps.setTimestamp(8, Timestamp.from(expiresAt));
                ps.setTimestamp(9, Timestamp.from(now));
                ps.setTimestamp(10, Timestamp.from(now));
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    TotpFactor factor = (TotpFactor) rowToFactor(rs);
                    String secretB32 = base32Encode(secret).replaceAll("=+$", "");
                    String otpauthUri = Totp.otpauthUri(secret, identifier, "Flametrench");
                    return new TotpEnrollmentResult(factor, secretB32, otpauthUri);
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public WebAuthnEnrollmentResult enrollWebAuthnFactor(
            String usrId, String identifier, byte[] publicKey, long signCount, String rpId
    ) {
        try (Connection conn = dataSource.getConnection()) {
            UUID userUuid = requireUserActiveForMfa(conn, usrId);
            Instant now = now();
            UUID mfaUuid = UUID.fromString(Id.decode(Id.generate("mfa")).uuid());
            Instant expiresAt = now.plusSeconds(PENDING_FACTOR_TTL_SECONDS);
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO mfa (id, usr_id, type, status, identifier,"
                  + " webauthn_public_key, webauthn_sign_count, webauthn_rp_id,"
                  + " pending_expires_at, created_at, updated_at)"
                  + " VALUES (?, ?, 'webauthn', 'pending', ?, ?, ?, ?, ?, ?, ?)"
                  + " RETURNING " + MFA_COLS)) {
                ps.setObject(1, mfaUuid);
                ps.setObject(2, userUuid);
                ps.setString(3, identifier);
                ps.setBytes(4, publicKey);
                ps.setLong(5, signCount);
                ps.setString(6, rpId);
                ps.setTimestamp(7, Timestamp.from(expiresAt));
                ps.setTimestamp(8, Timestamp.from(now));
                ps.setTimestamp(9, Timestamp.from(now));
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return new WebAuthnEnrollmentResult((WebAuthnFactor) rowToFactor(rs));
                }
            }
        } catch (SQLException e) {
            if (isUniqueViolation(e)) {
                throw new PreconditionError(
                        "WebAuthn credential \"" + identifier + "\" is already enrolled",
                        "duplicate_webauthn_credential"
                );
            }
            throw new RuntimeException(e);
        }
    }

    @Override
    public RecoveryEnrollmentResult enrollRecoveryFactor(String usrId) {
        try (Connection conn = dataSource.getConnection()) {
            UUID userUuid = requireUserActiveForMfa(conn, usrId);
            Instant now = now();
            String[] codes = RecoveryCodes.generateSet();
            String[] hashes = new String[codes.length];
            Boolean[] consumed = new Boolean[codes.length];
            for (int i = 0; i < codes.length; i++) {
                hashes[i] = PasswordHashing.hash(codes[i]);
                consumed[i] = Boolean.FALSE;
            }
            UUID mfaUuid = UUID.fromString(Id.decode(Id.generate("mfa")).uuid());
            Array hashArray = conn.createArrayOf("text", hashes);
            Array consumedArray = conn.createArrayOf("boolean", consumed);
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO mfa (id, usr_id, type, status,"
                  + " recovery_hashes, recovery_consumed, created_at, updated_at)"
                  + " VALUES (?, ?, 'recovery', 'active', ?, ?, ?, ?)"
                  + " RETURNING " + MFA_COLS)) {
                ps.setObject(1, mfaUuid);
                ps.setObject(2, userUuid);
                ps.setArray(3, hashArray);
                ps.setArray(4, consumedArray);
                ps.setTimestamp(5, Timestamp.from(now));
                ps.setTimestamp(6, Timestamp.from(now));
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return new RecoveryEnrollmentResult(
                            (RecoveryFactor) rowToFactor(rs),
                            Arrays.asList(codes)
                    );
                }
            }
        } catch (SQLException e) {
            if (isUniqueViolation(e)) {
                throw new PreconditionError(
                        "User " + usrId + " already has an active recovery factor; revoke before re-enrolling",
                        "active_singleton_exists"
                );
            }
            throw new RuntimeException(e);
        }
    }

    @Override
    public Factor getMfaFactor(String mfaId) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT " + MFA_COLS + " FROM mfa WHERE id = ?")) {
            ps.setObject(1, wireToUuid(mfaId));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new NotFoundError("MFA factor " + mfaId + " not found");
                return rowToFactor(rs);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public List<Factor> listMfaFactors(String usrId) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT " + MFA_COLS + " FROM mfa WHERE usr_id = ? ORDER BY created_at")) {
            ps.setObject(1, wireToUuid(usrId));
            try (ResultSet rs = ps.executeQuery()) {
                List<Factor> rows = new ArrayList<>();
                while (rs.next()) rows.add(rowToFactor(rs));
                return List.copyOf(rows);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private static class MfaRowDirect {
        UUID id;
        UUID usrId;
        String type;
        String status;
        String identifier;
        byte[] totpSecret;
        long webauthnSignCount;
        byte[] webauthnPublicKey;
        String webauthnRpId;
        String[] recoveryHashes;
        Boolean[] recoveryConsumed;
        Instant pendingExpiresAt;
    }

    private MfaRowDirect lockMfa(Connection conn, String mfaId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, usr_id, type, status, identifier,"
              + " totp_secret, webauthn_public_key, webauthn_sign_count, webauthn_rp_id,"
              + " recovery_hashes, recovery_consumed, pending_expires_at"
              + " FROM mfa WHERE id = ? FOR UPDATE")) {
            ps.setObject(1, wireToUuid(mfaId));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new NotFoundError("MFA factor " + mfaId + " not found");
                MfaRowDirect r = new MfaRowDirect();
                r.id = (UUID) rs.getObject("id");
                r.usrId = (UUID) rs.getObject("usr_id");
                r.type = rs.getString("type");
                r.status = rs.getString("status");
                r.identifier = rs.getString("identifier");
                r.totpSecret = rs.getBytes("totp_secret");
                r.webauthnPublicKey = rs.getBytes("webauthn_public_key");
                r.webauthnSignCount = rs.getLong("webauthn_sign_count");
                r.webauthnRpId = rs.getString("webauthn_rp_id");
                Array hArray = rs.getArray("recovery_hashes");
                Array cArray = rs.getArray("recovery_consumed");
                if (hArray != null) {
                    Object[] hs = (Object[]) hArray.getArray();
                    r.recoveryHashes = new String[hs.length];
                    for (int i = 0; i < hs.length; i++) r.recoveryHashes[i] = (String) hs[i];
                }
                if (cArray != null) {
                    Object[] cs = (Object[]) cArray.getArray();
                    r.recoveryConsumed = new Boolean[cs.length];
                    for (int i = 0; i < cs.length; i++) r.recoveryConsumed[i] = (Boolean) cs[i];
                }
                Timestamp pe = rs.getTimestamp("pending_expires_at");
                r.pendingExpiresAt = pe != null ? pe.toInstant() : null;
                return r;
            }
        }
    }

    private void checkPendingNotExpired(MfaRowDirect r) {
        if (!"pending".equals(r.status)) return;
        if (r.pendingExpiresAt != null && now().isAfter(r.pendingExpiresAt)) {
            throw new PreconditionError(
                    "Pending factor " + Id.encode("mfa", r.id.toString()) + " expired",
                    "pending_factor_expired"
            );
        }
    }

    @Override
    public TotpFactor confirmTotpFactor(String mfaId, String code) {
        return tx(conn -> {
            MfaRowDirect r = lockMfa(conn, mfaId);
            if (!"totp".equals(r.type)) {
                throw new CredentialTypeMismatchError("Factor " + mfaId + " is " + r.type + ", not totp");
            }
            if (!"pending".equals(r.status)) {
                throw new PreconditionError(
                        "Factor " + mfaId + " is " + r.status + "; only pending factors confirm",
                        "factor_not_pending"
                );
            }
            checkPendingNotExpired(r);
            if (!Totp.verify(r.totpSecret, code, now().getEpochSecond())) {
                throw new InvalidCredentialError("TOTP code did not verify");
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE mfa SET status = 'active', pending_expires_at = NULL"
                  + " WHERE id = ? RETURNING " + MFA_COLS)) {
                ps.setObject(1, r.id);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return (TotpFactor) rowToFactor(rs);
                }
            }
        });
    }

    @Override
    public WebAuthnFactor confirmWebAuthnFactor(
            String mfaId,
            byte[] authenticatorData, byte[] clientDataJson, byte[] signature,
            byte[] expectedChallenge, String expectedOrigin
    ) {
        return tx(conn -> {
            MfaRowDirect r = lockMfa(conn, mfaId);
            if (!"webauthn".equals(r.type)) {
                throw new CredentialTypeMismatchError("Factor " + mfaId + " is " + r.type + ", not webauthn");
            }
            if (!"pending".equals(r.status)) {
                throw new PreconditionError(
                        "Factor " + mfaId + " is " + r.status + "; only pending factors confirm",
                        "factor_not_pending"
                );
            }
            checkPendingNotExpired(r);
            WebAuthnAssertionResult result = WebAuthn.verifyAssertion(
                    r.webauthnPublicKey, r.webauthnSignCount, r.webauthnRpId,
                    expectedChallenge, expectedOrigin,
                    authenticatorData, clientDataJson, signature
            );
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE mfa SET status = 'active', webauthn_sign_count = ?, pending_expires_at = NULL"
                  + " WHERE id = ? RETURNING " + MFA_COLS)) {
                ps.setLong(1, result.newSignCount());
                ps.setObject(2, r.id);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return (WebAuthnFactor) rowToFactor(rs);
                }
            }
        });
    }

    @Override
    public Factor revokeMfaFactor(String mfaId) {
        return tx(conn -> {
            MfaRowDirect r = lockMfa(conn, mfaId);
            if ("revoked".equals(r.status)) {
                return getMfaFactor(mfaId);
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE mfa SET status = 'revoked', pending_expires_at = NULL"
                  + " WHERE id = ? RETURNING " + MFA_COLS)) {
                ps.setObject(1, r.id);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return rowToFactor(rs);
                }
            }
        });
    }

    @Override
    public MfaVerifyResult verifyMfa(String usrId, MfaProof proof) {
        if (proof instanceof TotpProof p) return verifyTotpProof(usrId, p.code());
        if (proof instanceof WebAuthnProof p) return verifyWebAuthnProof(usrId, p);
        if (proof instanceof RecoveryProof p) return verifyRecoveryProof(usrId, p.code());
        throw new InvalidCredentialError("Unsupported MFA proof type");
    }

    private MfaVerifyResult verifyTotpProof(String usrId, String code) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT id, totp_secret FROM mfa"
                   + " WHERE usr_id = ? AND type = 'totp' AND status = 'active'")) {
            ps.setObject(1, wireToUuid(usrId));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new InvalidCredentialError("No active TOTP factor for user");
                byte[] secret = rs.getBytes("totp_secret");
                if (!Totp.verify(secret, code, now().getEpochSecond())) {
                    throw new InvalidCredentialError("TOTP code did not verify");
                }
                return new MfaVerifyResult(
                        Id.encode("mfa", rs.getString("id")),
                        FactorType.TOTP,
                        now(),
                        null
                );
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private MfaVerifyResult verifyWebAuthnProof(String usrId, WebAuthnProof proof) {
        return tx(conn -> {
            UUID userUuid = wireToUuid(usrId);
            UUID rowId;
            byte[] publicKey;
            long signCount;
            String rpId;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT id, usr_id, webauthn_public_key, webauthn_sign_count, webauthn_rp_id"
                  + " FROM mfa WHERE identifier = ? AND type = 'webauthn' AND status = 'active'"
                  + " FOR UPDATE")) {
                ps.setString(1, proof.credentialId());
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        throw new InvalidCredentialError("No WebAuthn factor for credential id");
                    }
                    UUID rowUsr = (UUID) rs.getObject("usr_id");
                    if (!rowUsr.equals(userUuid)) {
                        throw new InvalidCredentialError("WebAuthn factor does not belong to user");
                    }
                    rowId = (UUID) rs.getObject("id");
                    publicKey = rs.getBytes("webauthn_public_key");
                    signCount = rs.getLong("webauthn_sign_count");
                    rpId = rs.getString("webauthn_rp_id");
                }
            }
            WebAuthnAssertionResult result = WebAuthn.verifyAssertion(
                    publicKey, signCount, rpId,
                    proof.expectedChallenge(), proof.expectedOrigin(),
                    proof.authenticatorData(), proof.clientDataJson(), proof.signature()
            );
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE mfa SET webauthn_sign_count = ? WHERE id = ?")) {
                ps.setLong(1, result.newSignCount());
                ps.setObject(2, rowId);
                ps.executeUpdate();
            }
            return new MfaVerifyResult(
                    Id.encode("mfa", rowId.toString()),
                    FactorType.WEBAUTHN,
                    now(),
                    result.newSignCount()
            );
        });
    }

    private MfaVerifyResult verifyRecoveryProof(String usrId, String code) {
        String normalized = RecoveryCodes.normalizeInput(code);
        if (!RecoveryCodes.isValid(normalized)) {
            throw new InvalidCredentialError("Recovery code is malformed");
        }
        return tx(conn -> {
            UUID rowId;
            String[] hashes;
            Boolean[] consumed;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT id, recovery_hashes, recovery_consumed FROM mfa"
                  + " WHERE usr_id = ? AND type = 'recovery' AND status = 'active'"
                  + " FOR UPDATE")) {
                ps.setObject(1, wireToUuid(usrId));
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        throw new InvalidCredentialError("No active recovery factor for user");
                    }
                    rowId = (UUID) rs.getObject("id");
                    Object[] hs = (Object[]) rs.getArray("recovery_hashes").getArray();
                    Object[] cs = (Object[]) rs.getArray("recovery_consumed").getArray();
                    hashes = new String[hs.length];
                    consumed = new Boolean[cs.length];
                    for (int i = 0; i < hs.length; i++) hashes[i] = (String) hs[i];
                    for (int i = 0; i < cs.length; i++) consumed[i] = (Boolean) cs[i];
                }
            }
            // Walk every active slot regardless of an early match to keep
            // work constant relative to the active set.
            int matched = -1;
            for (int i = 0; i < hashes.length; i++) {
                if (Boolean.TRUE.equals(consumed[i])) continue;
                if (PasswordHashing.verify(hashes[i], normalized) && matched == -1) {
                    matched = i;
                }
            }
            if (matched == -1) {
                throw new InvalidCredentialError("Recovery code did not verify");
            }
            consumed[matched] = Boolean.TRUE;
            Array updated = conn.createArrayOf("boolean", consumed);
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE mfa SET recovery_consumed = ? WHERE id = ?")) {
                ps.setArray(1, updated);
                ps.setObject(2, rowId);
                ps.executeUpdate();
            }
            return new MfaVerifyResult(
                    Id.encode("mfa", rowId.toString()),
                    FactorType.RECOVERY,
                    now(),
                    null
            );
        });
    }

    @Override
    public UserMfaPolicy getMfaPolicy(String usrId) {
        UUID uuid = wireToUuid(usrId);
        try (Connection conn = dataSource.getConnection()) {
            try (PreparedStatement ps = conn.prepareStatement("SELECT id FROM usr WHERE id = ?")) {
                ps.setObject(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) throw new NotFoundError("User " + usrId + " not found");
                }
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT usr_id, required, grace_until, updated_at FROM usr_mfa_policy WHERE usr_id = ?")) {
                ps.setObject(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) return null;
                    return rowToPolicy(rs);
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public UserMfaPolicy setMfaPolicy(String usrId, boolean required, Instant graceUntil) {
        UUID uuid = wireToUuid(usrId);
        try (Connection conn = dataSource.getConnection()) {
            try (PreparedStatement ps = conn.prepareStatement("SELECT id FROM usr WHERE id = ?")) {
                ps.setObject(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) throw new NotFoundError("User " + usrId + " not found");
                }
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO usr_mfa_policy (usr_id, required, grace_until)"
                  + " VALUES (?, ?, ?)"
                  + " ON CONFLICT (usr_id) DO UPDATE SET"
                  + "   required = EXCLUDED.required,"
                  + "   grace_until = EXCLUDED.grace_until"
                  + " RETURNING usr_id, required, grace_until, updated_at")) {
                ps.setObject(1, uuid);
                ps.setBoolean(2, required);
                if (graceUntil != null) {
                    ps.setTimestamp(3, Timestamp.from(graceUntil));
                } else {
                    ps.setNull(3, Types.TIMESTAMP_WITH_TIMEZONE);
                }
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return rowToPolicy(rs);
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /** RFC 4648 base32 encoding (with padding). Inlined to mirror InMemoryIdentityStore. */
    private static String base32Encode(byte[] buf) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int bits = 0;
        int value = 0;
        StringBuilder out = new StringBuilder();
        for (byte b : buf) {
            value = (value << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                out.append(alphabet.charAt((value >>> (bits - 5)) & 0x1F));
                bits -= 5;
            }
        }
        if (bits > 0) {
            out.append(alphabet.charAt((value << (5 - bits)) & 0x1F));
        }
        while (out.length() % 8 != 0) out.append('=');
        return out.toString();
    }
}
