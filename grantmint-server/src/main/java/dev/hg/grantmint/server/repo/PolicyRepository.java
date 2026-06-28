package dev.hg.grantmint.server.repo;

import dev.hg.grantmint.server.domain.Policy;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** License templates/tiers, unique per product by {@code code}. */
public interface PolicyRepository extends JpaRepository<Policy, UUID> {

    Optional<Policy> findByProduct_IdAndCode(UUID productId, String code);

    List<Policy> findByProduct_Id(UUID productId);
}
