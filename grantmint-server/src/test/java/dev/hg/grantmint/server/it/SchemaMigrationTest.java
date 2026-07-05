package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Verifies the Flyway migration set (V1 schema, V2 indexes) applies cleanly against a real
 * PostgreSQL and that the security-critical invariants of the schema hold. Booting the full
 * Spring context here also exercises Hibernate {@code ddl-auto: validate}, proving the JPA
 * entity mapping agrees with the Flyway-created tables column-for-column.
 */
@SpringBootTest
class SchemaMigrationTest extends PostgresIntegrationTest {

    @Autowired
    private DataSource dataSource;

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(dataSource);
    }

    @Test
    void contextLoadsWithFlywayMigrationsApplied() {
        // The context started, so Flyway migrated and Hibernate validated the mapping.
        Integer applied =
                jdbc().queryForObject("SELECT count(*) FROM flyway_schema_history WHERE success = true", Integer.class);
        assertThat(applied).isGreaterThanOrEqualTo(2); // V1 + V2 at minimum
    }

    @Test
    void allCoreTablesExist() {
        List<String> tables = jdbc().queryForList(
                        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'", String.class);
        assertThat(tables)
                .contains(
                        "products",
                        "signing_keys",
                        "api_keys",
                        "policies",
                        "entitlements",
                        "licenses",
                        "machine_activations",
                        "webhook_events",
                        "audit_log");
    }

    @Test
    void validationIndexesExist() {
        List<String> indexes =
                jdbc().queryForList("SELECT indexname FROM pg_indexes WHERE schemaname = 'public'", String.class);
        assertThat(indexes)
                .contains(
                        "ix_activations_license_active",
                        "ix_licenses_expiry_sweep",
                        "ix_activations_heartbeat",
                        "ix_licenses_entitlements_gin",
                        "ix_policies_code"); // V6: the webhook policy-map resolver's code-only lookup
    }

    @Test
    void keyIdLookupIsServedByTheFullUniqueIndexNotTheDroppedPartialOne() {
        List<String> indexes =
                jdbc().queryForList("SELECT indexname FROM pg_indexes WHERE schemaname = 'public'", String.class);
        // V5 dropped the partial WHERE status='active' index: the validation lookup is status-agnostic
        // (it must classify revoked/suspended/expired licenses), so PostgreSQL can never plan the
        // partial index — the V1 unique B-tree on key_id serves the hot-path lookup instead.
        assertThat(indexes).doesNotContain("ix_licenses_key_id_active").contains("uq_licenses_key_id");
    }

    @Test
    void privateKeyRefGuardRejectsRawBytesAcceptsPointer() {
        JdbcTemplate jdbc = jdbc();
        jdbc.update("INSERT INTO products (slug, name) VALUES ('guard-test', 'Guard Test')");
        String productId = jdbc.queryForObject("SELECT id::text FROM products WHERE slug = 'guard-test'", String.class);

        byte[] pub = new byte[32]; // 32-byte all-zero public key satisfies the length CHECK

        // A non-pointer ref (looks like raw key material) must be rejected by the guard.
        assertThatThrownBy(() -> jdbc.update(
                        "INSERT INTO signing_keys (key_id, product_id, public_key, private_key_ref)"
                                + " VALUES ('k-bad', ?::uuid, ?, 'AAAAraw-key-bytes')",
                        productId,
                        pub))
                .hasMessageContaining("ck_signing_keys_ref_is_pointer");

        // A proper pointer scheme is accepted.
        int rows = jdbc.update(
                "INSERT INTO signing_keys (key_id, product_id, public_key, private_key_ref)"
                        + " VALUES ('k-good', ?::uuid, ?, 'file:/etc/grantmint/keys/ed25519.key')",
                productId,
                pub);
        assertThat(rows).isEqualTo(1);
    }
}
