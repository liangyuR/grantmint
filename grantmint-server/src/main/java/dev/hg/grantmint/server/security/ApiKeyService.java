package dev.hg.grantmint.server.security;

import dev.hg.grantmint.server.domain.ApiKey;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.repo.ApiKeyRepository;
import dev.hg.grantmint.server.repo.ProductRepository;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Lifecycle and authentication for issuance and validation API keys (Schemes 2 and 3).
 *
 * <p>Keys are minted by an admin, scoped to one product, stored as a SHA-256 hash plus a display
 * prefix, and returned in plaintext exactly once. Authentication hashes the presented key, looks it
 * up by hash, re-compares in constant time, checks revocation/expiry, and records {@code
 * last_used_at}. See docs/features/ADMIN_AND_API_AUTH.md.
 */
@Service
public class ApiKeyService {

    private final ApiKeyRepository apiKeys;
    private final ProductRepository products;
    private final ApiKeyGenerator generator;
    private final Clock clock;

    public ApiKeyService(ApiKeyRepository apiKeys, ProductRepository products, ApiKeyGenerator generator, Clock clock) {
        this.apiKeys = apiKeys;
        this.products = products;
        this.generator = generator;
        this.clock = clock;
    }

    /**
     * Mint a product-scoped key. The returned {@link GeneratedApiKey#plaintext()} is the only copy
     * of the secret — it is never persisted and must be shown to the operator exactly once.
     *
     * @throws NoSuchElementException if no product has the given id
     * @throws IllegalArgumentException if {@code scope} is {@link ApiKeyScope#ADMIN} (admin auth is
     *     the session scheme, not a product-scoped key)
     */
    @Transactional
    public MintedKey createProductKey(UUID productId, ApiKeyScope scope, ApiKeyEnvironment environment, String name) {
        if (scope == ApiKeyScope.ADMIN) {
            throw new IllegalArgumentException("Admin keys are not product-scoped; use admin session auth.");
        }
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("A key name/label is required.");
        }
        Product product = products.findById(productId)
                .orElseThrow(() -> new NoSuchElementException("No product with id " + productId));

        GeneratedApiKey generated = generator.generate(scope, environment);
        ApiKey entity = new ApiKey();
        entity.setProduct(product);
        entity.setName(name);
        entity.setKeyHash(generated.keyHash());
        entity.setKeyPrefix(generated.keyPrefix());
        entity.setScope(scope.wire());
        apiKeys.save(entity);
        return new MintedKey(entity, generated.plaintext());
    }

    /** All keys for a product, newest first. The hash is never exposed — callers surface metadata only. */
    @Transactional(readOnly = true)
    public List<ApiKey> listForProduct(UUID productId) {
        if (!products.existsById(productId)) {
            throw new NoSuchElementException("No product with id " + productId);
        }
        return apiKeys.findByProduct_IdOrderByCreatedAtDesc(productId);
    }

    /**
     * Revoke a key by id, scoped to a product so a cross-product revoke is impossible. Idempotent:
     * re-revoking a revoked key leaves the original {@code revoked_at} untouched.
     *
     * @throws NoSuchElementException if the key does not exist or belongs to another product
     */
    @Transactional
    public void revoke(UUID productId, UUID apiKeyId) {
        ApiKey key = apiKeys.findById(apiKeyId)
                .filter(k -> k.getProduct() != null
                        && productId.equals(k.getProduct().getId()))
                .orElseThrow(() -> new NoSuchElementException("No API key " + apiKeyId + " for product " + productId));
        if (key.getRevokedAt() == null) {
            key.setRevokedAt(OffsetDateTime.now(clock));
        }
    }

    /**
     * Authenticate a presented key by its <em>own</em> namespace, whatever that is. Used by the
     * issuance chain so a real-but-wrong-scope key (e.g. a validation key sent to {@code /issuance})
     * still authenticates and is then denied by the authority rule with a 403 — "I know who you are,
     * but you may not do this" — rather than a 401. Returns empty for an unrecognised namespace.
     */
    @Transactional
    public Optional<ResolvedKey> resolveByNamespace(String presented) {
        ApiKeyScope scope = scopeForNamespace(presented);
        return scope == null ? Optional.empty() : resolve(presented, scope);
    }

    private static ApiKeyScope scopeForNamespace(String presented) {
        if (presented == null) {
            return null;
        }
        if (presented.startsWith("gm_live_") || presented.startsWith("gm_test_")) {
            return ApiKeyScope.ISSUANCE;
        }
        if (presented.startsWith("gm_val_")) {
            return ApiKeyScope.VALIDATION;
        }
        if (presented.startsWith("gm_admin_")) {
            return ApiKeyScope.ADMIN;
        }
        return null;
    }

    /**
     * Authenticate a presented key against the expected scheme. Returns the product scope on success,
     * or empty for any failure (unknown key, wrong scope, revoked, or expired) — callers must not
     * distinguish these to the client.
     */
    @Transactional
    public Optional<ResolvedKey> resolve(String presented, ApiKeyScope expectedScope) {
        if (presented == null || presented.isBlank()) {
            return Optional.empty();
        }
        String presentedHash = Secrets.sha256Hex(presented);
        Optional<ApiKey> found = apiKeys.findByKeyHash(presentedHash);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        ApiKey key = found.get();
        // Defence in depth: re-compare the hash in constant time after the lookup.
        if (!Secrets.constantTimeEqualsHex(presentedHash, key.getKeyHash())) {
            return Optional.empty();
        }
        if (!expectedScope.wire().equals(key.getScope())) {
            return Optional.empty();
        }
        OffsetDateTime now = OffsetDateTime.now(clock);
        if (key.getRevokedAt() != null) {
            return Optional.empty();
        }
        if (key.getExpiresAt() != null && !key.getExpiresAt().isAfter(now)) {
            return Optional.empty();
        }
        key.setLastUsedAt(now);
        UUID productId = key.getProduct() == null ? null : key.getProduct().getId();
        return Optional.of(new ResolvedKey(key.getId(), productId, expectedScope));
    }

    /**
     * A successfully authenticated API key, reduced to what authorization needs.
     *
     * @param apiKeyId the row id, for audit/attribution
     * @param productId the product the key is scoped to (null only for global admin keys)
     * @param scope the authenticated scheme
     */
    public record ResolvedKey(UUID apiKeyId, UUID productId, ApiKeyScope scope) {}

    /**
     * A freshly minted key: the persisted row plus the one-time {@code plaintext}. The plaintext is
     * never stored — the caller must surface it to the operator exactly once and then discard it.
     *
     * @param apiKey the persisted key row (metadata only; hash is internal)
     * @param plaintext the full secret, shown once
     */
    public record MintedKey(ApiKey apiKey, String plaintext) {}
}
