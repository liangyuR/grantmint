package dev.hg.grantmint.server.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * Append-only audit trail of who issued, revoked, or otherwise changed what. Target references are
 * intentionally loose (not FK-constrained) so audit rows survive target deletion. See
 * docs/architecture/DATABASE_SCHEMA.md.
 */
@Entity
@Table(name = "audit_log")
public class AuditLog {

    @Id
    @GeneratedValue
    private UUID id;

    /** Admin username, API key ID, or e.g. {@code webhook:stripe}. */
    @Column(nullable = false)
    private String actor;

    /** Allowed values: admin | api_key | webhook | system. */
    @Column(name = "actor_type", nullable = false)
    private String actorType;

    /** Action token, e.g. {@code license.issued} or {@code license.revoked}. */
    @Column(nullable = false)
    private String action;

    /** Entity type affected, e.g. {@code license} | {@code policy} | {@code product}. */
    @Column(name = "target_type", nullable = false)
    private String targetType;

    /** Loose reference to the affected entity ID; nullable to support system-level events. */
    @Column(name = "target_id")
    private String targetId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> detail = new HashMap<>();

    /** Request IP address (PII-adjacent). Mapped as PostgreSQL {@code inet}. */
    @JdbcTypeCode(SqlTypes.INET)
    @Column(name = "ip_address")
    private String ipAddress;

    @CreationTimestamp
    @Column(name = "occurred_at", nullable = false, updatable = false)
    private OffsetDateTime occurredAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getActor() {
        return actor;
    }

    public void setActor(String actor) {
        this.actor = actor;
    }

    public String getActorType() {
        return actorType;
    }

    public void setActorType(String actorType) {
        this.actorType = actorType;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getTargetType() {
        return targetType;
    }

    public void setTargetType(String targetType) {
        this.targetType = targetType;
    }

    public String getTargetId() {
        return targetId;
    }

    public void setTargetId(String targetId) {
        this.targetId = targetId;
    }

    public Map<String, Object> getDetail() {
        return detail;
    }

    public void setDetail(Map<String, Object> detail) {
        this.detail = detail;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public OffsetDateTime getOccurredAt() {
        return occurredAt;
    }
}
