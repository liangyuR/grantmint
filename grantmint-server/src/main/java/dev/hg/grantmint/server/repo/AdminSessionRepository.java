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

    /**
     * Revoke every live session for an operator ("log out everywhere"). This is a JPQL bulk update,
     * which bypasses the persistence context, so both {@code @Modifying} escape hatches are needed:
     * {@code flushAutomatically} pushes pending same-transaction changes (the password-change flow
     * rehashes the credential on {@code admin_users}, whose query space does not overlap this
     * statement's, so Hibernate would not auto-flush it — clearing first would silently discard it);
     * {@code clearAutomatically} then evicts stale first-level-cache entities so a session loaded
     * earlier in the transaction cannot still read {@code revokedAt = null} and authenticate a
     * just-revoked token.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update AdminSession s set s.revokedAt = :now "
            + "where s.adminUser.id = :adminUserId and s.revokedAt is null")
    int revokeAllForUser(@Param("adminUserId") UUID adminUserId, @Param("now") OffsetDateTime now);
}
