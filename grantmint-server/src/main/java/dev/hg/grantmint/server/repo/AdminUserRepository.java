package dev.hg.grantmint.server.repo;

import dev.hg.grantmint.server.domain.AdminUser;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Admin operators (Scheme 1). Login resolves by username; bootstrap checks emptiness. */
public interface AdminUserRepository extends JpaRepository<AdminUser, UUID> {

    Optional<AdminUser> findByUsername(String username);
}
