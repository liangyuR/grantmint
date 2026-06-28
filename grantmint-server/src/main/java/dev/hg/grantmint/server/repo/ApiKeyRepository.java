package dev.hg.grantmint.server.repo;

import dev.hg.grantmint.server.domain.ApiKey;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * API keys. Authentication looks up by the secret's hash (never the plaintext); the hash column
 * is unique and indexed.
 */
public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {

    Optional<ApiKey> findByKeyHash(String keyHash);

    /** All keys minted for a product, newest first — for the admin list view (hashes never shown). */
    List<ApiKey> findByProduct_IdOrderByCreatedAtDesc(UUID productId);
}
