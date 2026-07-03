package dev.hg.grantmint.server.signing;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.crypto.Ed25519Verifier;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.domain.SigningKey;
import dev.hg.grantmint.server.repo.ProductRepository;
import dev.hg.grantmint.server.repo.SigningKeyRepository;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Manages Ed25519 signing keys: registers a product's key (public bytes + a private-key pointer)
 * and mints {@link Ed25519Signer}s on demand for the issuance flow.
 *
 * <p>Two invariants make this the trust anchor of issuance:
 *
 * <ol>
 *   <li><b>Private bytes never persist.</b> Only the 32-byte public key and a {@code private_key_ref}
 *       pointer are stored. The seed is dereferenced via {@link PrivateKeySeedResolver} at signer-
 *       build time and wiped from memory immediately after. 🔒
 *   <li><b>The registered public key provably matches the private seed.</b> Registration signs a
 *       probe with the resolved private key and verifies it under the supplied public key; a mismatch
 *       is rejected before anything is written, so a token can never be signed by a key whose public
 *       half clients do not hold.
 * </ol>
 *
 * <p>See docs/architecture/ARCHITECTURE.md (the issuance flow).
 */
@Service
public class SigningKeyService {

    /** Fixed probe signed at registration to prove the keypair matches. Not a secret. */
    private static final byte[] KEYPAIR_PROBE = "grantmint-signing-key-probe".getBytes(StandardCharsets.UTF_8);

    private final SigningKeyRepository signingKeys;
    private final ProductRepository products;
    private final PrivateKeySeedResolver seedResolver;

    public SigningKeyService(
            SigningKeyRepository signingKeys, ProductRepository products, PrivateKeySeedResolver seedResolver) {
        this.signingKeys = signingKeys;
        this.products = products;
        this.seedResolver = seedResolver;
    }

    /**
     * Register a signing key for a product. Resolves the private seed from {@code privateKeyRef},
     * proves it matches {@code rawPublicKey}, persists the public key + pointer metadata, and
     * optionally makes it the product's active signing key.
     *
     * @param keyId the short signing-key id (the token header {@code kid}); the row's primary key
     * @param rawPublicKey the raw 32-byte Ed25519 public key clients embed
     * @throws NoSuchElementException if the product does not exist
     * @throws SigningKeyException if the ref cannot be resolved or the public key does not match
     */
    @Transactional
    public SigningKey register(
            UUID productId, String keyId, String privateKeyRef, byte[] rawPublicKey, boolean makeActive) {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(privateKeyRef, "privateKeyRef");
        Objects.requireNonNull(rawPublicKey, "rawPublicKey");
        if (rawPublicKey.length != Ed25519Keys.RAW_KEY_LENGTH) {
            throw new SigningKeyException("Ed25519 public key must be " + Ed25519Keys.RAW_KEY_LENGTH + " bytes");
        }
        Product product = products.findById(productId)
                .orElseThrow(() -> new NoSuchElementException("Product not found: " + productId));

        proveKeyPairMatches(keyId, privateKeyRef, rawPublicKey);

        SigningKey key = new SigningKey();
        key.setKeyId(keyId);
        key.setProduct(product);
        key.setAlgorithm("Ed25519");
        key.setPublicKey(rawPublicKey.clone());
        key.setPrivateKeyRef(privateKeyRef);
        key.setStatus("active");
        SigningKey saved = signingKeys.save(key);

        if (makeActive) {
            product.setActiveSigningKeyId(keyId);
            products.save(product);
        }
        return saved;
    }

    /**
     * List every signing key registered for a product, newest first.
     *
     * @throws NoSuchElementException if the product does not exist
     */
    @Transactional(readOnly = true)
    public List<SigningKey> listForProduct(UUID productId) {
        if (!products.existsById(productId)) {
            throw new NoSuchElementException("Product not found: " + productId);
        }
        return signingKeys.findByProduct_IdOrderByCreatedAtDesc(productId);
    }

    /** Build a signer for a product's <em>active</em> signing key. */
    @Transactional(readOnly = true)
    public Ed25519Signer signerForProduct(UUID productId) {
        Product product = products.findById(productId)
                .orElseThrow(() -> new NoSuchElementException("Product not found: " + productId));
        String keyId = product.getActiveSigningKeyId();
        if (keyId == null) {
            throw new SigningKeyException("Product has no active signing key: " + productId);
        }
        return signerForKeyId(keyId);
    }

    /** Build a signer for a specific signing-key id by dereferencing its private-key pointer. */
    @Transactional(readOnly = true)
    public Ed25519Signer signerForKeyId(String keyId) {
        SigningKey key = signingKeys
                .findById(keyId)
                .orElseThrow(() -> new NoSuchElementException("Signing key not found: " + keyId));
        if (!"active".equals(key.getStatus())) {
            throw new SigningKeyException("Signing key '" + keyId + "' is not active (status=" + key.getStatus() + ")");
        }
        return buildSigner(keyId, key.getPrivateKeyRef());
    }

    /** The raw 32-byte public key for a signing-key id, for offline/online verification. */
    @Transactional(readOnly = true)
    public byte[] rawPublicKey(String keyId) {
        return signingKeys
                .findById(keyId)
                .orElseThrow(() -> new NoSuchElementException("Signing key not found: " + keyId))
                .getPublicKey()
                .clone();
    }

    private void proveKeyPairMatches(String keyId, String privateKeyRef, byte[] rawPublicKey) {
        Ed25519Signer signer = buildSigner(keyId, privateKeyRef);
        byte[] signature = signer.sign(KEYPAIR_PROBE);
        Ed25519Verifier verifier;
        try {
            verifier = Ed25519Verifier.fromRaw(rawPublicKey);
        } catch (RuntimeException e) {
            throw new SigningKeyException("Supplied public key is not a valid Ed25519 point", e);
        }
        if (!verifier.verify(KEYPAIR_PROBE, signature)) {
            throw new SigningKeyException(
                    "Supplied public key does not match the private key behind the ref for '" + keyId + "'");
        }
    }

    /** Resolve the seed, build the signer, and wipe the seed from memory. */
    private Ed25519Signer buildSigner(String keyId, String privateKeyRef) {
        byte[] seed = seedResolver.resolveSeed(privateKeyRef);
        try {
            return Ed25519Signer.fromRawSeed(seed, keyId);
        } finally {
            Arrays.fill(seed, (byte) 0);
        }
    }
}
