package dev.hg.grantmint.server.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;

/**
 * An opaque, server-side admin session. Only the SHA-256 hash of the {@code gm_sess_…} bearer token
 * is stored; the token is shown once at login. Deleting or revoking the row kills the session
 * instantly — the admin surface favours revocability over statelessness. See
 * docs/features/ADMIN_AND_API_AUTH.md.
 */
@Entity
@Table(
        name = "admin_sessions",
        uniqueConstraints = @UniqueConstraint(name = "uq_admin_sessions_token_hash", columnNames = "token_hash"))
public class AdminSession {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "admin_user_id", nullable = false)
    private AdminUser adminUser;

    /** SHA-256 hex of the opaque session token. The token itself is never stored. */
    @Column(name = "token_hash", nullable = false)
    private String tokenHash;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "last_used_at", nullable = false)
    private OffsetDateTime lastUsedAt;

    @Column(name = "expires_at", nullable = false)
    private OffsetDateTime expiresAt;

    @Column(name = "revoked_at")
    private OffsetDateTime revokedAt;

    /**
     * Safety net for the NOT NULL {@code last_used_at} column. The service sets it at login and on
     * every resolve; Hibernate sends an explicit value for mapped columns, so the SQL {@code DEFAULT
     * now()} is bypassed. If a future caller ever persists a session without setting it, default it
     * here so the bug surfaces as a usable timestamp rather than a constraint violation.
     */
    @PrePersist
    void defaultLastUsedAt() {
        if (lastUsedAt == null) {
            lastUsedAt = OffsetDateTime.now();
        }
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public AdminUser getAdminUser() {
        return adminUser;
    }

    public void setAdminUser(AdminUser adminUser) {
        this.adminUser = adminUser;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public void setTokenHash(String tokenHash) {
        this.tokenHash = tokenHash;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getLastUsedAt() {
        return lastUsedAt;
    }

    public void setLastUsedAt(OffsetDateTime lastUsedAt) {
        this.lastUsedAt = lastUsedAt;
    }

    public OffsetDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(OffsetDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public OffsetDateTime getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(OffsetDateTime revokedAt) {
        this.revokedAt = revokedAt;
    }
}
