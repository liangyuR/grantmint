package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.domain.AuditLog;
import dev.hg.grantmint.server.repo.AuditLogRepository;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Database-backed checks for the append-only audit writer: an entry persists with the lowercase
 * actor-type token, and — because the (target_type, target_id) reference is deliberately not
 * FK-constrained — an audit row survives deletion of the entity it describes.
 */
@SpringBootTest
class AuditServiceIntegrationTest extends PostgresIntegrationTest {

    @Autowired
    private AuditService auditService;

    @Autowired
    private AuditLogRepository auditLog;

    @Test
    void recordsAnEntryWithLowercaseActorType() {
        AuditLog saved = auditService.record(
                "admin@example.com",
                AuditActorType.ADMIN,
                "license.issued",
                "license",
                "GMNT-7F3A-9K2D-XQ41",
                Map.of("policy", "pro-annual"));

        assertThat(saved.getId()).isNotNull();
        assertThat(saved.getActorType()).isEqualTo("admin");

        var found = auditLog.findByTargetTypeAndTargetIdOrderByOccurredAtDesc("license", "GMNT-7F3A-9K2D-XQ41");
        assertThat(found).anySatisfy(e -> assertThat(e.getAction()).isEqualTo("license.issued"));
    }

    @Test
    void auditRowSurvivesWithLooseUnconstrainedTargetReference() {
        // target_id points at a free-form id that need not exist as a row — no FK.
        String orphanTarget = "policy-that-will-be-deleted";
        auditService.record("webhook:stripe", AuditActorType.WEBHOOK, "policy.deleted", "policy", orphanTarget);

        var found = auditLog.findByTargetTypeAndTargetIdOrderByOccurredAtDesc("policy", orphanTarget);
        assertThat(found).hasSize(1);
        assertThat(found.get(0).getActor()).isEqualTo("webhook:stripe");
    }
}
