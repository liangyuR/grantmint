package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.MachineActivationRepository;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

/**
 * Proves the hot-path repository queries CAN use the indexes the schema doc says back them — the
 * regression class the post-M13 audit caught: {@code findByHolderEmailIgnoreCase} was a derived
 * query compiling to {@code UPPER(holder_email)}, which the {@code lower(holder_email)} expression
 * index could never serve, so every lookup silently seq-scanned while the behavior tests stayed
 * green.
 *
 * <p>Method: capture the <em>actual Hibernate-generated SQL</em> with a {@link
 * RecordingStatementInspector}, then {@code EXPLAIN} it under {@code enable_seqscan = off} and
 * {@code plan_cache_mode = force_generic_plan}. The generic plan is the strict test: it must prove
 * index eligibility from the SQL text alone, with no help from concrete parameter values — exactly
 * the discipline behind the literal-status predicates in {@code MachineActivationRepository} and
 * {@code LicenseRepository#findExpiryCandidates}.
 */
@SpringBootTest(
        properties = "spring.jpa.properties.hibernate.session_factory.statement_inspector="
                + "dev.hg.grantmint.server.it.RecordingStatementInspector")
@Transactional
class QueryIndexEligibilityIntegrationTest extends PostgresIntegrationTest {

    @Autowired
    private LicenseRepository licenses;

    @Autowired
    private MachineActivationRepository activations;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void holderEmailLookupCanUseTheLowerExpressionIndex() {
        RecordingStatementInspector.clear();
        licenses.findByHolderEmailIgnoreCase("someone@example.com");
        String sql = RecordingStatementInspector.lastContaining("holder_email");

        String plan = explainGenericPlanWithoutSeqScan(sql, "'someone@example.com'");

        assertThat(plan)
                .as("the generated SQL must be servable by ix_licenses_holder_email (V2):%n%s%n%s", sql, plan)
                .contains("ix_licenses_holder_email");
    }

    @Test
    void activeSeatCountCanUseThePartialActivationsIndex() {
        RecordingStatementInspector.clear();
        activations.countActiveByLicenseId(UUID.randomUUID());
        String sql = RecordingStatementInspector.lastContaining("machine_activations");

        String plan = explainGenericPlanWithoutSeqScan(sql, "'" + UUID.randomUUID() + "'");

        // Both V2 activation indexes are partial on status = 'active', so the planner choosing
        // EITHER proves the point: the literal predicate makes the partial indexes provable from
        // the statement text alone. The old bound-parameter form made neither provable under a
        // generic plan. (On the test's empty table the two are cost-identical; which one wins is
        // planner noise, not a property worth pinning.)
        assertThat(plan)
                .as("the generated SQL must be servable by a partial status='active' index (V2):%n%s%n%s", sql, plan)
                .containsPattern("ix_activations_(license_active|heartbeat)");
    }

    /**
     * EXPLAIN the given JDBC-parameterized SQL as PostgreSQL's <em>generic</em> plan with
     * sequential scans priced out: the resulting plan names an index if and only if the statement
     * text alone proves the index applicable. {@code SET LOCAL} scopes the planner knobs to the
     * test transaction; the prepared statement is session-scoped, so it is deallocated before the
     * (pooled) connection can leak it into another test.
     */
    private String explainGenericPlanWithoutSeqScan(String jdbcSql, String... literalArgs) {
        String numbered = numberPlaceholders(jdbcSql);
        jdbc.execute("SET LOCAL enable_seqscan = off");
        jdbc.execute("SET LOCAL plan_cache_mode = force_generic_plan");
        jdbc.execute("PREPARE index_eligibility_probe AS " + numbered);
        try {
            return String.join(
                    "\n",
                    jdbc.queryForList(
                            "EXPLAIN EXECUTE index_eligibility_probe(" + String.join(", ", literalArgs) + ")",
                            String.class));
        } finally {
            jdbc.execute("DEALLOCATE index_eligibility_probe");
        }
    }

    /** JDBC {@code ?} placeholders as PostgreSQL's {@code $1..$n} (none of these queries quote a ?). */
    private static String numberPlaceholders(String sql) {
        StringBuilder out = new StringBuilder(sql.length() + 8);
        int n = 0;
        for (char c : sql.toCharArray()) {
            if (c == '?') {
                out.append('$').append(++n);
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
