package dev.hg.grantmint.server.repo;

import dev.hg.grantmint.server.domain.Product;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Products: lookup by URL-safe slug for admin and issuance flows. */
public interface ProductRepository extends JpaRepository<Product, UUID> {

    Optional<Product> findBySlug(String slug);

    boolean existsBySlug(String slug);
}
