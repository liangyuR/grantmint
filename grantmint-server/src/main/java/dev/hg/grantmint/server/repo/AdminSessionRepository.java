package dev.hg.grantmint.server.repo;

import dev.hg.grantmint.server.domain.AdminSession;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/** Server-side admin sessions (Scheme 1). Resolution is by token hash; revocation is per-row or per-user. */
public interface AdminSessionRepository extends JpaRepository<AdminSession, UUID> {

    Optional<AdminSession> findByTokenHash(String tokenHash);

    /** Revoke every live session for an operator ("log out everywhere"). */
    @Modifying
    @Query("update AdminSession s set s.revokedAt = :now "
            + "where s.adminUser.id = :adminUserId and s.revokedAt is null")
    int revokeAllForUser(@Param("adminUserId") UUID adminUserId, @Param("now") OffsetDateTime now);
}
