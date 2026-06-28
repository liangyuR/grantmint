package dev.hg.grantmint.server.audit;

import dev.hg.grantmint.server.domain.AuditLog;
import dev.hg.grantmint.server.repo.AuditLogRepository;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Append-only writer for the audit trail. Records "who did what to which target" for every
 * mintable action (issue/suspend/reinstate/revoke, key creation, etc.).
 *
 * <p>The trail is deliberately append-only — this service exposes no update or delete. Audit rows
 * use a loose {@code (target_type, target_id)} reference with no foreign key, so they survive
 * deletion of the target they describe. See docs/architecture/DATABASE_SCHEMA.md.
 */
@Service
public class AuditService {

    private final AuditLogRepository repository;

    public AuditService(AuditLogRepository repository) {
        this.repository = repository;
    }

    /**
     * Append an audit entry. Participates in the caller's transaction so the trail stays consistent
     * with the action it records (if the action rolls back, so does its audit row).
     *
     * @param actor who acted — an admin username, an API-key id, or e.g. {@code webhook:stripe}
     * @param actorType the category of actor
     * @param action the action performed, e.g. {@code license.issued}
     * @param targetType the kind of entity acted upon, e.g. {@code license}
     * @param targetId the target's identifier (nullable for non-entity actions)
     * @param detail action-specific structured data (nullable → recorded as empty)
     */
    @Transactional
    public AuditLog record(
            String actor,
            AuditActorType actorType,
            String action,
            String targetType,
            String targetId,
            Map<String, Object> detail) {
        AuditLog entry = new AuditLog();
        entry.setActor(actor);
        entry.setActorType(actorType.wire());
        entry.setAction(action);
        entry.setTargetType(targetType);
        entry.setTargetId(targetId);
        if (detail != null && !detail.isEmpty()) {
            entry.setDetail(detail);
        }
        return repository.save(entry);
    }

    /** Convenience overload for actions with no structured detail. */
    @Transactional
    public AuditLog record(String actor, AuditActorType actorType, String action, String targetType, String targetId) {
        return record(actor, actorType, action, targetType, targetId, Map.of());
    }
}
