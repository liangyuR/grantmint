package dev.hg.grantmint.server.repo;

import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import jakarta.persistence.LockModeType;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * Licenses: the validation hot-path lookup is by the short online {@code key_id}. Also serves the
 * customer (holder-email) and billing ({@code external_ref}) lookups and the expiry-sweep job.
 *
 * <p>{@link JpaSpecificationExecutor} backs the admin list endpoint's optional-AND filters (status,
 * holder email, product, policy, key id) without a combinatorial explosion of derived-query methods.
 */
public interface LicenseRepository extends JpaRepository<License, UUID>, JpaSpecificationExecutor<License> {

    /** Primary online lookup for validate/activate/heartbeat/revoke. */
    Optional<License> findByKeyId(String keyId);

    /**
     * Validation-snapshot lookup: like {@link #findByKeyId} but eagerly joins the product so the
     * snapshot loader reads {@code product_id} in the same round-trip instead of triggering a lazy
     * second SELECT on every cache miss.
     */
    @Query("select l from License l join fetch l.product where l.keyId = :keyId")
    Optional<License> findByKeyIdWithProduct(@Param("keyId") String keyId);

    boolean existsByKeyId(String keyId);

    /** Backs the {@code grantmint.licenses.active} gauge, sampled on every Prometheus scrape. */
    long countByStatus(LicenseStatus status);

    /**
     * Locking variant for the seat-counting activation transaction: takes a pessimistic write lock
     * on the license row before counting active seats. See docs/features/ACTIVATION_AND_SEATS.md.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select l from License l where l.keyId = :keyId")
    Optional<License> findByKeyIdForUpdate(@Param("keyId") String keyId);

    /**
     * "List a customer's licenses" — case-insensitive email match. Explicit JPQL {@code lower()} on
     * purpose: Spring Data's derived {@code IgnoreCase} keyword compiles to {@code
     * UPPER(holder_email) = UPPER(?)}, which the expression index {@code ix_licenses_holder_email ON
     * licenses (lower(holder_email))} (V2) can never serve — every lookup would silently seq-scan
     * (post-M13 audit). This form matches the index's expression exactly, like the admin list
     * endpoint's {@code cb.lower(...)} Specification.
     */
    @Query("select l from License l where lower(l.holderEmail) = lower(:holderEmail)")
    List<License> findByHolderEmailIgnoreCase(@Param("holderEmail") String holderEmail);

    List<License> findByExternalRef(String externalRef);

    /**
     * Expiry-sweep candidates: sweepable ({@code active}/{@code suspended}) licenses with a concrete
     * expiry already in the past. The per-policy grace window is applied by the sweep job (M7).
     *
     * <p>Native SQL with the status list as <b>literal text</b>, not a bind-parameter collection, on
     * purpose: the partial index {@code ix_licenses_expiry_sweep} carries {@code WHERE status IN
     * ('active','suspended')}, and PostgreSQL can only plan a partial index when the query's
     * predicate provably implies the index's. A parameterized {@code in :statuses} stops being
     * provable once the planner switches to a generic plan, silently degrading the sweep to a full
     * scan (M13 audit) — the literal predicate matches the index's exactly, always. The status set
     * here mirrors the state machine's EXPIRE-capable states; V2 documents the same pairing on the
     * index side.
     */
    @Query(
            value = "select * from licenses"
                    + " where status in ('active', 'suspended')"
                    + " and expires_at is not null and expires_at < :cutoff",
            nativeQuery = true)
    List<License> findExpiryCandidates(@Param("cutoff") OffsetDateTime cutoff);
}
