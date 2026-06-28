package dev.hg.grantmint.server.repo;

import dev.hg.grantmint.server.domain.AuditLog;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Append-only audit trail; queried by the loose (target_type, target_id) reference. */
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    List<AuditLog> findByTargetTypeAndTargetIdOrderByOccurredAtDesc(String targetType, String targetId);
}
