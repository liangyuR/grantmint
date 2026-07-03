package dev.hg.grantmint.server.repo;

import dev.hg.grantmint.server.domain.SigningKey;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

/** Signing-key metadata (public key + pointer only). Keyed by the short {@code kid}. */
public interface SigningKeyRepository extends JpaRepository<SigningKey, String> {

    List<SigningKey> findByProduct_IdAndStatus(java.util.UUID productId, String status);

    List<SigningKey> findByProduct_IdOrderByCreatedAtDesc(java.util.UUID productId);
}
