package dev.hg.grantmint.server.repo;

import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import jakarta.persistence.LockModeType;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * Licenses: the validation hot-path lookup is by the short online {@code key_id}. Also serves the
 * customer (holder-email) and billing ({@code external_ref}) lookups and the expiry-sweep job.
 */
public interface LicenseRepository extends JpaRepository<License, UUID> {

    /** Primary online lookup for validate/activate/heartbeat/revoke. */
    Optional<License> findByKeyId(String keyId);

    boolean existsByKeyId(String keyId);

    /**
     * Locking variant for the seat-counting activation transaction: takes a pessimistic write lock
     * on the license row before counting active seats. See docs/features/ACTIVATION_AND_SEATS.md.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select l from License l where l.keyId = :keyId")
    Optional<License> findByKeyIdForUpdate(@Param("keyId") String keyId);

    /** "List a customer's licenses" — case-insensitive email match (backed by a lower() index). */
    List<License> findByHolderEmailIgnoreCase(String holderEmail);

    List<License> findByExternalRef(String externalRef);

    /**
     * Expiry-sweep candidates: non-terminal licenses with a concrete expiry already in the past.
     * The per-policy grace window is applied by the sweep job (M7).
     *
     * <p>{@code status} is an {@code AttributeConverter}-backed enum ({@code LicenseStatusConverter}),
     * not {@code @Enumerated}. The {@code in :statuses} comparison therefore relies on Hibernate 6
     * applying the converter to the bound {@link LicenseStatus} values — correct on Spring Boot 3 /
     * Hibernate 6, but the dependency is implicit, so callers pass {@code LicenseStatus} constants
     * (e.g. {@code ACTIVE}, {@code SUSPENDED}), never their wire strings.
     */
    @Query("select l from License l"
            + " where l.status in :statuses and l.expiresAt is not null and l.expiresAt < :cutoff")
    List<License> findExpiryCandidates(
            @Param("statuses") Collection<LicenseStatus> statuses, @Param("cutoff") OffsetDateTime cutoff);
}
