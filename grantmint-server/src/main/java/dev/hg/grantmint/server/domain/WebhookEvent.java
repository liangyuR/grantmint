package dev.hg.grantmint.server.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * Ingested billing webhook event from an external provider (e.g. Stripe, Polar). Idempotent via
 * provider event ID — each provider event is processed at most once. See
 * docs/architecture/DATABASE_SCHEMA.md.
 */
@Entity
@Table(name = "webhook_events")
public class WebhookEvent {

    @Id
    @GeneratedValue
    private UUID id;

    /** NULL when the event has not yet been correlated to a specific product. */
    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "product_id", nullable = true)
    private Product product;

    /** e.g. {@code stripe} | {@code polar}. */
    @Column(nullable = false)
    private String provider;

    /** Provider-assigned event ID, e.g. Stripe {@code evt_...}. Unique per provider. */
    @Column(name = "provider_event_id", nullable = false)
    private String providerEventId;

    /** e.g. {@code customer.subscription.deleted}. */
    @Column(name = "event_type", nullable = false)
    private String eventType;

    /** Allowed values: received | processed | failed | ignored. */
    @Column(nullable = false)
    private String status = "received";

    /** Raw verified event body from the provider. */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> payload = new HashMap<>();

    @Column(name = "signature_valid", nullable = false)
    private boolean signatureValid;

    @CreationTimestamp
    @Column(name = "received_at", nullable = false, updatable = false)
    private OffsetDateTime receivedAt;

    @Column(name = "processed_at")
    private OffsetDateTime processedAt;

    @Column(name = "error_detail")
    private String errorDetail;

    /**
     * ID of the license created or modified as a result of processing this event. Plain UUID — not
     * an association, because the row must survive license deletion (ON DELETE SET NULL in the DB).
     */
    @Column(name = "resulting_license_id")
    private UUID resultingLicenseId;

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

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getProviderEventId() {
        return providerEventId;
    }

    public void setProviderEventId(String providerEventId) {
        this.providerEventId = providerEventId;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Map<String, Object> getPayload() {
        return payload;
    }

    public void setPayload(Map<String, Object> payload) {
        this.payload = payload;
    }

    public boolean isSignatureValid() {
        return signatureValid;
    }

    public void setSignatureValid(boolean signatureValid) {
        this.signatureValid = signatureValid;
    }

    public OffsetDateTime getReceivedAt() {
        return receivedAt;
    }

    public OffsetDateTime getProcessedAt() {
        return processedAt;
    }

    public void setProcessedAt(OffsetDateTime processedAt) {
        this.processedAt = processedAt;
    }

    public String getErrorDetail() {
        return errorDetail;
    }

    public void setErrorDetail(String errorDetail) {
        this.errorDetail = errorDetail;
    }

    public UUID getResultingLicenseId() {
        return resultingLicenseId;
    }

    public void setResultingLicenseId(UUID resultingLicenseId) {
        this.resultingLicenseId = resultingLicenseId;
    }
}
