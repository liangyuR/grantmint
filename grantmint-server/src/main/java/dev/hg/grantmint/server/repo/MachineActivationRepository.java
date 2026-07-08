package dev.hg.grantmint.server.repo;

import dev.hg.grantmint.server.domain.MachineActivation;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * Machine activations (seats). The seat count drives node-locked enforcement; the heartbeat sweep
 * deactivates devices that stopped checking in.
 */
public interface MachineActivationRepository extends JpaRepository<MachineActivation, UUID> {

    /** Idempotent re-activation: at most one row per (license, fingerprint). */
    Optional<MachineActivation> findByLicense_IdAndFingerprint(UUID licenseId, String fingerprint);

    /**
     * Active seat count for a license (used inside the activation transaction). The {@code active}
     * status is a JPQL <b>literal</b>, not a bind parameter, for the same reason as {@link
     * LicenseRepository#findExpiryCandidates}: the partial index {@code ix_activations_license_active}
     * (V2) only covers rows {@code WHERE status = 'active'}, and PostgreSQL can only choose it when
     * the query's predicate provably implies the index's — a bound parameter stops being provable
     * under a generic plan (post-M13 audit). {@link #countActiveByKeyId} and {@link #findStaleActive}
     * follow the same discipline.
     */
    @Query("select count(a) from MachineActivation a" + " where a.license.id = :licenseId and a.status = 'active'")
    long countActiveByLicenseId(@Param("licenseId") UUID licenseId);

    /** Active seat count by the license's short key ID. */
    @Query("select count(a) from MachineActivation a" + " where a.license.keyId = :keyId and a.status = 'active'")
    long countActiveByKeyId(@Param("keyId") String keyId);

    /**
     * Active seat counts for a whole page of licenses in ONE query — the admin license list used to
     * issue {@link #countActiveByKeyId} once per row (a bounded N+1, post-M13 audit). Licenses with
     * no active seats simply have no row here; callers default them to zero. Same
     * literal-{@code 'active'} discipline as the counts above so the partial index stays eligible.
     */
    @Query("select a.license.id, count(a) from MachineActivation a"
            + " where a.license.id in :licenseIds and a.status = 'active' group by a.license.id")
    List<Object[]> countActiveByLicenseIds(@Param("licenseIds") List<UUID> licenseIds);

    /** Total occupied seats — backs the {@code grantmint.seats.used} gauge, sampled on scrape. */
    @Query("select count(a) from MachineActivation a where a.status = 'active'")
    long countActive();

    List<MachineActivation> findByLicense_Id(UUID licenseId);

    /**
     * Heartbeat-timeout sweep candidates: active activations whose last heartbeat is older than the
     * given cutoff. The per-policy timeout (3× the heartbeat interval) is computed by the job (M7).
     *
     * <p>This takes a single, already-computed cutoff and so is only correct when the caller has
     * applied a uniform timeout. Because policies may set different {@code heartbeat_interval_seconds},
     * the sweep job (M7) must either pass the most-permissive (largest) effective cutoff or iterate
     * per policy — this query intentionally stays policy-agnostic.
     */
    @Query("select a from MachineActivation a" + " where a.status = 'active' and a.lastHeartbeatAt < :cutoff")
    List<MachineActivation> findStaleActive(@Param("cutoff") OffsetDateTime cutoff);
}
