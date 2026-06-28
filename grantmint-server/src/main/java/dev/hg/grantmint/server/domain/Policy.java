package dev.hg.grantmint.server.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

/**
 * License template / tier for a product. Every license issued under a policy inherits its
 * activation type, seat count, duration, and entitlements (which may be overridden at issuance
 * time). See docs/architecture/DATABASE_SCHEMA.md.
 */
@Entity
@Table(
        name = "policies",
        uniqueConstraints =
                @UniqueConstraint(
                        name = "uq_policies_product_code",
                        columnNames = {"product_id", "code"}))
public class Policy {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;

    /** Machine-readable tier code, e.g. {@code pro-annual}. Unique per product. */
    @Column(nullable = false)
    private String code;

    /** Human-readable display name, e.g. {@code Pro Annual}. */
    @Column(nullable = false)
    private String name;

    /** Allowed values: node_locked | floating. */
    @Column(name = "activation_type", nullable = false)
    private String activationType = "node_locked";

    @Column(name = "max_seats", nullable = false)
    private int maxSeats = 1;

    /** Days until expiry; NULL means perpetual. */
    @Column(name = "duration_days")
    private Integer durationDays;

    @Column(name = "grace_period_days", nullable = false)
    private int gracePeriodDays = 0;

    @Column(name = "is_trial", nullable = false)
    private boolean trial = false;

    /**
     * Denormalized snapshot of this policy's entitlements, serialised identically to what is
     * embedded in the signed token. The normalised source of truth is the {@code entitlements}
     * table.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> entitlements = new HashMap<>();

    /** Optional issuance-time constraints embedded into every token issued under this policy. */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> constraints = new HashMap<>();

    @Column(name = "heartbeat_interval_seconds", nullable = false)
    private int heartbeatIntervalSeconds = 86400;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public Product getProduct() {
        return product;
    }

    public void setProduct(Product product) {
        this.product = product;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getActivationType() {
        return activationType;
    }

    public void setActivationType(String activationType) {
        this.activationType = activationType;
    }

    public int getMaxSeats() {
        return maxSeats;
    }

    public void setMaxSeats(int maxSeats) {
        this.maxSeats = maxSeats;
    }

    public Integer getDurationDays() {
        return durationDays;
    }

    public void setDurationDays(Integer durationDays) {
        this.durationDays = durationDays;
    }

    public int getGracePeriodDays() {
        return gracePeriodDays;
    }

    public void setGracePeriodDays(int gracePeriodDays) {
        this.gracePeriodDays = gracePeriodDays;
    }

    public boolean isTrial() {
        return trial;
    }

    public void setTrial(boolean trial) {
        this.trial = trial;
    }

    public Map<String, Object> getEntitlements() {
        return entitlements;
    }

    public void setEntitlements(Map<String, Object> entitlements) {
        this.entitlements = entitlements;
    }

    public Map<String, Object> getConstraints() {
        return constraints;
    }

    public void setConstraints(Map<String, Object> constraints) {
        this.constraints = constraints;
    }

    public int getHeartbeatIntervalSeconds() {
        return heartbeatIntervalSeconds;
    }

    public void setHeartbeatIntervalSeconds(int heartbeatIntervalSeconds) {
        this.heartbeatIntervalSeconds = heartbeatIntervalSeconds;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }
}
