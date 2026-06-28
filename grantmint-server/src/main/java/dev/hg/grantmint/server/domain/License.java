package dev.hg.grantmint.server.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;
import org.springframework.data.domain.Persistable;

/**
 * An issued instance of a policy for a customer. PII-bearing (holder name and email). The signed
 * token is the offline artefact; key_id is the online lookup handle. See
 * docs/architecture/DATABASE_SCHEMA.md and docs/features/LICENSE_LIFECYCLE.md.
 */
@Entity
@Table(name = "licenses", uniqueConstraints = @UniqueConstraint(name = "uq_licenses_key_id", columnNames = "key_id"))
public class License implements Persistable<UUID> {

    /**
     * Application-assigned at construction (not {@code @GeneratedValue}) so issuance can embed this
     * id as the token's {@code lid} claim <em>before</em> persisting — the {@code signed_token}
     * column is NOT NULL, so the token must be built (which needs the id) before the row is written.
     */
    @Id
    private UUID id = UUID.randomUUID();

    /**
     * {@code true} until the row is persisted or loaded, so Spring Data {@code save()} issues a clean
     * INSERT for the assigned id rather than a SELECT-then-merge. See {@link #isNew()}.
     */
    @Transient
    private boolean newEntity = true;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "policy_id", nullable = false)
    private Policy policy;

    /** Short, human-readable online identifier, e.g. {@code K7P2-9QXM-4T1A}. Unique. */
    @Column(name = "key_id", nullable = false, unique = true)
    private String keyId;

    /** Full Ed25519-signed offline artefact (base64url). Immutable once written. */
    @Column(name = "signed_token", nullable = false)
    private String signedToken;

    /**
     * Short key ID of the signing key that minted this token, kept for rotation/audit. Plain
     * string — not an association, to avoid a join on the hot read path.
     */
    @Column(name = "signing_key_id", nullable = false)
    private String signingKeyId;

    @Convert(converter = LicenseStatusConverter.class)
    @Column(nullable = false, columnDefinition = "text")
    private LicenseStatus status = LicenseStatus.CREATED;

    /** PII — holder display name. */
    @Column(name = "holder_name")
    private String holderName;

    /** PII — holder email address. */
    @Column(name = "holder_email")
    private String holderEmail;

    /** Effective entitlements snapshot at issuance (copied from policy; may be overridden). */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> entitlements = new HashMap<>();

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> constraints = new HashMap<>();

    /** Snapshot of policy.max_seats at issuance time. */
    @Column(name = "max_seats", nullable = false)
    private int maxSeats;

    @CreationTimestamp
    @Column(name = "issued_at", nullable = false, updatable = false)
    private OffsetDateTime issuedAt;

    @Column(name = "activated_at")
    private OffsetDateTime activatedAt;

    /** NULL = perpetual license (no expiry). */
    @Column(name = "expires_at")
    private OffsetDateTime expiresAt;

    @Column(name = "suspended_at")
    private OffsetDateTime suspendedAt;

    @Column(name = "revoked_at")
    private OffsetDateTime revokedAt;

    @Column(name = "revocation_reason")
    private String revocationReason;

    /** External billing reference, e.g. a Stripe subscription ID. */
    @Column(name = "external_ref")
    private String externalRef;

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

    @Override
    public boolean isNew() {
        return newEntity;
    }

    @PostPersist
    @PostLoad
    void markPersisted() {
        this.newEntity = false;
    }

    public Product getProduct() {
        return product;
    }

    public void setProduct(Product product) {
        this.product = product;
    }

    public Policy getPolicy() {
        return policy;
    }

    public void setPolicy(Policy policy) {
        this.policy = policy;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getSignedToken() {
        return signedToken;
    }

    public void setSignedToken(String signedToken) {
        this.signedToken = signedToken;
    }

    public String getSigningKeyId() {
        return signingKeyId;
    }

    public void setSigningKeyId(String signingKeyId) {
        this.signingKeyId = signingKeyId;
    }

    public LicenseStatus getStatus() {
        return status;
    }

    public void setStatus(LicenseStatus status) {
        this.status = status;
    }

    public String getHolderName() {
        return holderName;
    }

    public void setHolderName(String holderName) {
        this.holderName = holderName;
    }

    public String getHolderEmail() {
        return holderEmail;
    }

    public void setHolderEmail(String holderEmail) {
        this.holderEmail = holderEmail;
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

    public int getMaxSeats() {
        return maxSeats;
    }

    public void setMaxSeats(int maxSeats) {
        this.maxSeats = maxSeats;
    }

    public OffsetDateTime getIssuedAt() {
        return issuedAt;
    }

    public OffsetDateTime getActivatedAt() {
        return activatedAt;
    }

    public void setActivatedAt(OffsetDateTime activatedAt) {
        this.activatedAt = activatedAt;
    }

    public OffsetDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(OffsetDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public OffsetDateTime getSuspendedAt() {
        return suspendedAt;
    }

    public void setSuspendedAt(OffsetDateTime suspendedAt) {
        this.suspendedAt = suspendedAt;
    }

    public OffsetDateTime getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(OffsetDateTime revokedAt) {
        this.revokedAt = revokedAt;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(String revocationReason) {
        this.revocationReason = revocationReason;
    }

    public String getExternalRef() {
        return externalRef;
    }

    public void setExternalRef(String externalRef) {
        this.externalRef = externalRef;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }
}
