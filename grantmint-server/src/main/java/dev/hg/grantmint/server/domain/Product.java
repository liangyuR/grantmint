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
 * A thing being licensed. Owns policies, signing keys, and issued licenses. See
 * docs/architecture/DATABASE_SCHEMA.md.
 */
@Entity
@Table(name = "products", uniqueConstraints = @UniqueConstraint(name = "uq_products_slug", columnNames = "slug"))
public class Product {

    @Id
    @GeneratedValue
    private UUID id;

    // Uniqueness is declared once, on the @Table constraint (uq_products_slug), which matches the
    // Flyway schema by name; a second @Column(unique=true) would be a redundant, unnamed duplicate.
    @Column(nullable = false)
    private String slug;

    @Column(nullable = false)
    private String name;

    private String description;

    /** Short key ID (kid) of the active signing key. The private key lives outside the DB. */
    @Column(name = "active_signing_key_id")
    private String activeSigningKeyId;

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

    public String getSlug() {
        return slug;
    }

    public void setSlug(String slug) {
        this.slug = slug;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getActiveSigningKeyId() {
        return activeSigningKeyId;
    }

    public void setActiveSigningKeyId(String activeSigningKeyId) {
        this.activeSigningKeyId = activeSigningKeyId;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }
}
