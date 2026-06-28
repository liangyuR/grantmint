package dev.hg.grantmint.server.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import org.hibernate.annotations.CreationTimestamp;

/**
 * Ed25519 key metadata and PUBLIC key only. The private signing key is never stored here — only a
 * reference pointer (e.g. {@code vault:secret/grantmint/sign#2026}). See
 * docs/architecture/DATABASE_SCHEMA.md.
 */
@Entity
@Table(name = "signing_keys")
public class SigningKey {

    /**
     * Application-assigned natural key, e.g. {@code ed25519-2026-01}. No {@code @GeneratedValue}
     * — callers supply this at issuance time.
     */
    @Id
    @Column(name = "key_id")
    private String keyId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;

    /** Always {@code Ed25519} (enforced by ck_signing_keys_algo). */
    @Column(nullable = false)
    private String algorithm = "Ed25519";

    /** 32-byte raw Ed25519 public key; also embedded in client SDKs. */
    @Column(name = "public_key", nullable = false)
    private byte[] publicKey;

    /**
     * Pointer to the private key — never the bytes. Allowed schemes: {@code file:}, {@code vault:},
     * {@code env:}, {@code awssm:}, {@code gcpsm:}, {@code sops:}.
     */
    @Column(name = "private_key_ref", nullable = false)
    private String privateKeyRef;

    /** Allowed values: active | rotating | retired. */
    @Column(nullable = false)
    private String status = "active";

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    /** Set when this key is superseded by a newer key. */
    @Column(name = "rotated_at")
    private OffsetDateTime rotatedAt;

    /** Set when this key is no longer trusted for verification. */
    @Column(name = "retired_at")
    private OffsetDateTime retiredAt;

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public Product getProduct() {
        return product;
    }

    public void setProduct(Product product) {
        this.product = product;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKeyRef() {
        return privateKeyRef;
    }

    public void setPrivateKeyRef(String privateKeyRef) {
        this.privateKeyRef = privateKeyRef;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getRotatedAt() {
        return rotatedAt;
    }

    public void setRotatedAt(OffsetDateTime rotatedAt) {
        this.rotatedAt = rotatedAt;
    }

    public OffsetDateTime getRetiredAt() {
        return retiredAt;
    }

    public void setRetiredAt(OffsetDateTime retiredAt) {
        this.retiredAt = retiredAt;
    }
}
