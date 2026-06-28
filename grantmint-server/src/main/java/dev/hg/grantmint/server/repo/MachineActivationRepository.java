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

    /** Active seat count for a license (used inside the activation transaction). */
    long countByLicense_IdAndStatus(UUID licenseId, String status);

    /** Active seat count by the license's short key ID. */
    @Query("select count(a) from MachineActivation a" + " where a.license.keyId = :keyId and a.status = 'active'")
    long countActiveByKeyId(@Param("keyId") String keyId);

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
