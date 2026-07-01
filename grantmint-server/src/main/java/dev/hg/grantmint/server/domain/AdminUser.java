package dev.hg.grantmint.server.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

/**
 * An operator who authenticates to the admin surface (Scheme 1). The password is stored only as an
 * Argon2id hash — never plaintext. See docs/features/ADMIN_AND_API_AUTH.md.
 */
@Entity
@Table(
        name = "admin_users",
        uniqueConstraints = @UniqueConstraint(name = "uq_admin_users_username", columnNames = "username"))
public class AdminUser {

    @Id
    @GeneratedValue
    private UUID id;

    // Uniqueness is declared once on the @Table constraint (uq_admin_users_username), which matches
    // the Flyway schema by name; a second @Column(unique=true) would be a redundant, unnamed duplicate.
    @Column(nullable = false)
    private String username;

    /** Argon2id PHC hash of the password. The plaintext is never stored. */
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    @Column(name = "disabled_at")
    private OffsetDateTime disabledAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }

    public OffsetDateTime getDisabledAt() {
        return disabledAt;
    }

    public void setDisabledAt(OffsetDateTime disabledAt) {
        this.disabledAt = disabledAt;
    }
}
