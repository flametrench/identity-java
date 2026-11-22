// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.identity;

import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.time.Clock;

@EnabledIfEnvironmentVariable(named = "IDENTITY_POSTGRES_URL", matches = ".+")
class PostgresAuthGatesTest extends AuthGatesContract {
    @Override
    protected IdentityStore newStore(Clock clock) {
        URI uri = URI.create(System.getenv("IDENTITY_POSTGRES_URL").replaceFirst("^postgresql:", "http:"));
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
        try (Connection conn = ds.getConnection(); Statement st = conn.createStatement()) {
            st.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;");
            st.execute(Files.readString(Path.of("src/test/resources/postgres-schema.sql")));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return new PostgresIdentityStore(ds, clock);
    }
}
