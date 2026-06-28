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
import org.hibernate.type.SqlTypes;

/**
 * A device that has activated a license. Each active row counts against the license's seat limit.
 * Seat enforcement is performed in application logic inside a transaction (SELECT FOR UPDATE on the
 * license, then count active rows). See docs/features/ACTIVATION_AND_SEATS.md.
 */
@Entity
@Table(
        name = "machine_activations",
        uniqueConstraints =
                @UniqueConstraint(
                        name = "uq_activations_license_fingerprint",
                        columnNames = {"license_id", "fingerprint"}))
public class MachineActivation {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "license_id", nullable = false)
    private License license;

    /** Stable device fingerprint (hashed hardware/OS signal). Unique per license. */
    @Column(nullable = false)
    private String fingerprint;

    /** Human-readable machine label; optional. */
    @Column(name = "machine_name")
    private String machineName;

    /** e.g. {@code macos} | {@code windows} | {@code linux}. */
    private String platform;

    /** Allowed values: active | deactivated | expired. */
    @Column(nullable = false)
    private String status = "active";

    @CreationTimestamp
    @Column(name = "activated_at", nullable = false, updatable = false)
    private OffsetDateTime activatedAt;

    /**
     * Timestamp of the most recent heartbeat. Initialised to creation time by
     * {@code @CreationTimestamp}; updated by heartbeat calls via the setter.
     */
    @CreationTimestamp
    @Column(name = "last_heartbeat_at", nullable = false)
    private OffsetDateTime lastHeartbeatAt;

    @Column(name = "deactivated_at")
    private OffsetDateTime deactivatedAt;

    /** Last seen IP address (PII-adjacent). Mapped as PostgreSQL {@code inet}. */
    @JdbcTypeCode(SqlTypes.INET)
    @Column(name = "ip_address")
    private String ipAddress;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> metadata = new HashMap<>();

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public License getLicense() {
        return license;
    }

    public void setLicense(License license) {
        this.license = license;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public String getMachineName() {
        return machineName;
    }

    public void setMachineName(String machineName) {
        this.machineName = machineName;
    }

    public String getPlatform() {
        return platform;
    }

    public void setPlatform(String platform) {
        this.platform = platform;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public OffsetDateTime getActivatedAt() {
        return activatedAt;
    }

    public OffsetDateTime getLastHeartbeatAt() {
        return lastHeartbeatAt;
    }

    public void setLastHeartbeatAt(OffsetDateTime lastHeartbeatAt) {
        this.lastHeartbeatAt = lastHeartbeatAt;
    }

    public OffsetDateTime getDeactivatedAt() {
        return deactivatedAt;
    }

    public void setDeactivatedAt(OffsetDateTime deactivatedAt) {
        this.deactivatedAt = deactivatedAt;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }
}
