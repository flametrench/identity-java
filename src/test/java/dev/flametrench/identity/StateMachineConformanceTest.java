// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.postgresql.ds.PGSimpleDataSource;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * State-machine conformance harness for the identity lifecycle and MFA
 * fixtures (user status gates, TOTP replay, recovery re-enrollment).
 *
 * <p>Each fixture runs against {@link InMemoryIdentityStore} and, when
 * {@code IDENTITY_POSTGRES_URL} is set, against {@link PostgresIdentityStore}.
 * Expected errors are matched by spec error name against the thrown
 * exception's class hierarchy, so a missing error class fails the vector
 * instead of breaking compilation.
 */
class StateMachineConformanceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern VAR_PATTERN = Pattern.compile("^\\{([a-z_][a-z0-9_]*)\\}$");
    private static final String DEFAULT_TOTP_IDENTIFIER = "conformance@example.com";

    private static final String[] FIXTURES = {
            "identity/user-status-gates.json",
            "identity/mfa/totp-replay-rejected.json",
            "identity/mfa/recovery-single-active-set.json",
    };

    /** A clock the {@code set_clock} pseudo-op can pin. */
    static final class MutableClock extends Clock {
        private Instant instant = Instant.now();

        void set(Instant i) { instant = i; }

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return instant; }
    }

    // ─── Store backends ───

    private static DataSource postgresDataSource() {
        String url = System.getenv("IDENTITY_POSTGRES_URL");
        if (url == null || url.isEmpty()) return null;
        URI uri = URI.create(url.replaceFirst("^postgresql:", "http:"));
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setServerNames(new String[] { uri.getHost() });
        ds.setPortNumbers(new int[] { uri.getPort() == -1 ? 5432 : uri.getPort() });
        String path = uri.getPath();
        ds.setDatabaseName(path != null && path.length() > 1 ? path.substring(1) : "postgres");
        if (uri.getUserInfo() != null) {
            String[] parts = uri.getUserInfo().split(":", 2);
            ds.setUser(parts[0]);
            if (parts.length > 1) ds.setPassword(parts[1]);
        }
        return ds;
    }

    private static Function<MutableClock, IdentityStore> postgresFactory(DataSource ds) {
        return clock -> {
            try (Connection conn = ds.getConnection(); Statement st = conn.createStatement()) {
                st.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;");
                st.execute(Files.readString(Path.of("src/test/resources/postgres-schema.sql")));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return new PostgresIdentityStore(ds, clock);
        };
    }

    // ─── Fixture plumbing ───

    private static JsonNode loadFixture(String relativePath) throws IOException {
        String resource = "/conformance/fixtures/" + relativePath;
        try (InputStream in = StateMachineConformanceTest.class.getResourceAsStream(resource)) {
            if (in == null) throw new IOException("Fixture not found: " + resource);
            return MAPPER.readTree(in);
        }
    }

    private static Object resolveVars(Object value, Map<String, Object> vars) {
        if (value instanceof String s) {
            Matcher m = VAR_PATTERN.matcher(s);
            if (m.matches()) {
                if (!vars.containsKey(m.group(1))) {
                    throw new IllegalStateException("Unknown variable in fixture: " + s);
                }
                return vars.get(m.group(1));
            }
            return s;
        }
        if (value instanceof List<?> list) {
            List<Object> out = new ArrayList<>();
            for (Object o : list) out.add(resolveVars(o, vars));
            return out;
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) out.put((String) e.getKey(), resolveVars(e.getValue(), vars));
            return out;
        }
        return value;
    }

    private static Object plain(JsonNode node) {
        return node == null || node.isNull() ? null : MAPPER.convertValue(node, Object.class);
    }

    private static Object walkPath(Object obj, String dotted) {
        Object cur = obj;
        for (String seg : dotted.split("\\.")) {
            if (cur instanceof Map<?, ?> m && m.containsKey(seg)) cur = m.get(seg);
            else if (cur instanceof List<?> l && seg.matches("\\d+")) cur = l.get(Integer.parseInt(seg));
            else throw new IllegalStateException("Cannot resolve '" + seg + "' in " + dotted);
        }
        return cur;
    }

    private static boolean isNamed(Throwable t, String errorName) {
        for (Class<?> c = t.getClass(); c != null; c = c.getSuperclass()) {
            if (c.getSimpleName().equals(errorName)) return true;
        }
        return false;
    }

    private static byte[] base32Decode(String s) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        String clean = s.replace("=", "").toUpperCase();
        byte[] out = new byte[clean.length() * 5 / 8];
        int buffer = 0, bits = 0, idx = 0;
        for (char ch : clean.toCharArray()) {
            buffer = (buffer << 5) | alphabet.indexOf(ch);
            bits += 5;
            if (bits >= 8) {
                out[idx++] = (byte) (buffer >> (bits - 8));
                bits -= 8;
            }
        }
        return out;
    }

    // ─── Ops ───

    @SuppressWarnings("unchecked")
    private static Object invokeOp(IdentityStore store, MutableClock clock, String op, Map<String, Object> a) {
        return switch (op) {
            case "set_clock" -> {
                clock.set(Instant.parse((String) a.get("now")));
                yield null;
            }
            case "create_user" -> Map.of("user", Map.of("id", store.createUser().id()));
            case "create_user_with_password_credential" -> {
                User u = store.createUser();
                PasswordCredential c = store.createPasswordCredential(
                        u.id(), (String) a.get("identifier"), (String) a.get("password"));
                yield Map.of("user", Map.of("id", u.id()), "credential", Map.of("id", c.id()));
            }
            case "suspend_user" -> store.suspendUser((String) a.get("usr_id"));
            case "reinstate_user" -> store.reinstateUser((String) a.get("usr_id"));
            case "revoke_user" -> store.revokeUser((String) a.get("usr_id"));
            case "verify_password" -> store.verifyPassword(
                    (String) a.get("identifier"), (String) a.get("password"));
            case "create_session" -> store.createSession(
                    (String) a.get("usr_id"), (String) a.get("cred_id"),
                    ((Number) a.get("ttl_seconds")).longValue());
            case "create_pat" -> {
                CreatePatResult r = store.createPat(new CreatePatInput(
                        (String) a.get("usr_id"), (String) a.get("name"),
                        (List<String>) a.get("scope"), null));
                yield Map.of("token", r.token(), "pat", Map.of("id", r.pat().id()));
            }
            case "verify_pat_token" -> store.verifyPatToken((String) a.get("token"));
            case "enroll_totp_factor" -> {
                TotpEnrollmentResult r = store.enrollTotpFactor(
                        (String) a.get("usr_id"), DEFAULT_TOTP_IDENTIFIER);
                yield Map.of("factor", Map.of("id", r.factor().id()), "secret", r.secretB32());
            }
            case "compute_totp_code" -> Map.of("code", Totp.compute(
                    base32Decode((String) a.get("secret")), clock.instant().getEpochSecond()));
            case "confirm_totp_factor" -> store.confirmTotpFactor(
                    (String) a.get("mfa_id"), (String) a.get("code"));
            case "verify_mfa" -> {
                Map<String, Object> proof = (Map<String, Object>) a.get("proof");
                String code = (String) proof.get("code");
                MfaProof p = switch ((String) proof.get("type")) {
                    case "totp" -> new TotpProof(code);
                    case "recovery" -> new RecoveryProof(code);
                    default -> throw new IllegalStateException("Unsupported proof type: " + proof.get("type"));
                };
                yield store.verifyMfa((String) a.get("usr_id"), p);
            }
            case "enroll_recovery_factor" -> {
                RecoveryEnrollmentResult r = store.enrollRecoveryFactor((String) a.get("usr_id"));
                yield Map.of("factor", Map.of("id", r.factor().id()), "codes", r.codes());
            }
            case "assert_active_mfa_factors" -> {
                long count = store.listMfaFactors((String) a.get("usr_id")).stream()
                        .filter(f -> f.type().getValue().equals(a.get("type")))
                        .filter(f -> f.status() == FactorStatus.ACTIVE)
                        .count();
                assertEquals(((Number) a.get("expected_count")).longValue(), count,
                        "active " + a.get("type") + " factors");
                yield null;
            }
            case "assert_mfa_factor_fields" -> {
                Factor f = store.getMfaFactor((String) a.get("mfa_id"));
                if (a.containsKey("expected_status")) {
                    assertEquals(a.get("expected_status"), f.status().getValue(), "status of " + f.id());
                }
                if (a.containsKey("expected_replaces")) {
                    assertEquals(a.get("expected_replaces"), f.replaces(), "replaces of " + f.id());
                }
                yield null;
            }
            default -> throw new IllegalStateException("Unknown fixture op: " + op);
        };
    }

    @SuppressWarnings("unchecked")
    private static void runTest(JsonNode test, Function<MutableClock, IdentityStore> factory) {
        MutableClock clock = new MutableClock();
        IdentityStore store = factory.apply(clock);
        Map<String, Object> vars = new HashMap<>();

        int stepNo = 0;
        for (JsonNode step : test.get("steps")) {
            stepNo++;
            String op = step.get("op").asText();
            Map<String, Object> input = (Map<String, Object>) resolveVars(plain(step.get("input")), vars);
            JsonNode expected = step.get("expected");

            if (expected != null && expected.has("error")) {
                String errorName = expected.get("error").asText();
                Object result;
                try {
                    result = invokeOp(store, clock, op, input);
                } catch (RuntimeException e) {
                    if (isNamed(e, errorName)) return;
                    fail("step " + stepNo + " (" + op + "): expected " + errorName
                            + " but got " + e.getClass().getSimpleName() + ": " + e.getMessage(), e);
                    return;
                }
                fail("step " + stepNo + " (" + op + "): expected " + errorName
                        + " but the call succeeded" + (result != null ? " with " + result : ""));
                return;
            }

            Object result;
            try {
                result = invokeOp(store, clock, op, input);
            } catch (RuntimeException e) {
                fail("step " + stepNo + " (" + op + "): expected success but got "
                        + e.getClass().getSimpleName() + ": " + e.getMessage(), e);
                return;
            }
            JsonNode captures = step.get("captures");
            if (captures != null) {
                Iterator<Map.Entry<String, JsonNode>> it = captures.fields();
                while (it.hasNext()) {
                    Map.Entry<String, JsonNode> e = it.next();
                    vars.put(e.getKey(), walkPath(result, e.getValue().asText()));
                }
            }
        }
    }

    private static List<DynamicNode> fixtureTests(Function<MutableClock, IdentityStore> factory) throws IOException {
        List<DynamicNode> out = new ArrayList<>();
        for (String path : FIXTURES) {
            List<DynamicTest> tests = new ArrayList<>();
            for (JsonNode t : loadFixture(path).get("tests")) {
                tests.add(DynamicTest.dynamicTest("[" + t.get("id").asText() + "]", () -> runTest(t, factory)));
            }
            out.add(DynamicContainer.dynamicContainer(path, tests));
        }
        return out;
    }

    @TestFactory
    List<DynamicNode> inMemory() throws IOException {
        return fixtureTests(InMemoryIdentityStore::new);
    }

    @TestFactory
    List<DynamicNode> postgres() throws IOException {
        DataSource ds = postgresDataSource();
        if (ds == null) return List.of();
        return fixtureTests(postgresFactory(ds));
    }
}
