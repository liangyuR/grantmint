package dev.hg.grantmint.server.activation;

import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.domain.MachineActivation;
import dev.hg.grantmint.server.repo.MachineActivationRepository;
import dev.hg.grantmint.server.validation.ValidationCache;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Frees seats held by devices that stopped checking in — the background half of
 * docs/features/ACTIVATION_AND_SEATS.md's "Heartbeats and heartbeat-timeout deactivation". A device
 * whose {@code last_heartbeat_at} is older than {@code 3 * policy.heartbeatIntervalSeconds} is
 * missed two heartbeats in a row and is treated as gone; its seat is released so the customer isn't
 * stuck paying for a laptop that was wiped.
 *
 * <p><b>Reaped rows are marked {@code expired}, not {@code reaped}.</b> docs/features/
 * ACTIVATION_AND_SEATS.md's ASCII diagram uses "reaped" as a label, but the {@code machine_activations}
 * table's {@code CHECK} constraint only permits {@code active | deactivated | expired} — the schema,
 * not the prose diagram, is the contract. "Expired" is also the semantically accurate word: the
 * activation's implicit lease (its heartbeat window) ran out, exactly like a license's {@code exp}.
 *
 * <p><b>Why the query and the timeout filter are split.</b> {@link MachineActivationRepository#findStaleActive}
 * takes one cutoff and is deliberately over-inclusive: it uses the most permissive cutoff possible
 * (now minus 3 * the DB's minimum allowed {@code heartbeat_interval_seconds}, 60s) so it never misses
 * a candidate whose policy has a shorter interval. This job then re-checks each candidate against its
 * own policy's actual {@code 3 * heartbeatIntervalSeconds} timeout before reaping, so a device on a
 * long-interval policy that merely looks stale under the permissive floor is correctly left active.
 */
@Component
public class HeartbeatReaperJob {

    private static final Logger log = LoggerFactory.getLogger(HeartbeatReaperJob.class);

    /** Wire value a reaped activation row is set to — see the class javadoc for why not "reaped". */
    static final String MACHINE_EXPIRED = "expired";

    /** The DB's minimum allowed {@code heartbeat_interval_seconds} (CHECK constraint floor). */
    private static final long MIN_HEARTBEAT_INTERVAL_SECONDS = 60;

    /** Hardcoded per TASKS.md ("heartbeat_interval_seconds * 3") — no config knob for the multiplier. */
    private static final int TIMEOUT_MULTIPLIER = 3;

    private final MachineActivationRepository activations;
    private final ValidationCache cache;
    private final AuditService audit;
    private final Clock clock;

    public HeartbeatReaperJob(
            MachineActivationRepository activations, ValidationCache cache, AuditService audit, Clock clock) {
        this.activations = activations;
        this.cache = cache;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * Reaper entry point, invoked on the configured interval (default every 5 minutes; see
     * {@code grantmint.activation.reaper-interval}).
     */
    @Scheduled(fixedDelayString = "${grantmint.activation.reaper-interval:PT5M}")
    @Transactional
    public void reap() {
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        OffsetDateTime mostPermissiveCutoff = now.minusSeconds(TIMEOUT_MULTIPLIER * MIN_HEARTBEAT_INTERVAL_SECONDS);
        List<MachineActivation> candidates = activations.findStaleActive(mostPermissiveCutoff);
        int reapedCount = 0;
        for (MachineActivation activation : candidates) {
            if (activation.getLicense().isOfflineDevice()) continue;
            // Lazy-loaded inside this transaction: each candidate's license may sit under a different
            // policy with a different heartbeat interval.
            int intervalSeconds = activation.getLicense().getPolicy().getHeartbeatIntervalSeconds();
            OffsetDateTime ownCutoff = now.minusSeconds((long) TIMEOUT_MULTIPLIER * intervalSeconds);
            if (!activation.getLastHeartbeatAt().isBefore(ownCutoff)) {
                continue; // stale under the permissive floor only — this policy's own timeout hasn't hit
            }
            reapOne(activation, now);
            reapedCount++;
        }
        if (reapedCount > 0) {
            // One audit entry per sweep run, not one per activation — a reaping run can touch many
            // rows and per-row entries would flood the trail with no added forensic value.
            audit.record(
                    "system",
                    AuditActorType.SYSTEM,
                    "activation.reaped",
                    "activation_sweep",
                    null,
                    Map.of("reaped", reapedCount));
            log.info("Heartbeat reaper expired {} stale activation(s)", reapedCount);
        }
    }

    private void reapOne(MachineActivation activation, OffsetDateTime now) {
        activation.setStatus(MACHINE_EXPIRED);
        activation.setDeactivatedAt(now);
        evictAfterCommit(activation.getLicense().getKeyId());
    }

    /**
     * Evict only after commit — evicting inline would let a concurrent validate re-cache the
     * pre-commit seat count and pin it stale for a full TTL. Same pattern as
     * {@link dev.hg.grantmint.server.activation.ActivationService}.
     */
    private void evictAfterCommit(String keyId) {
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                cache.evict(keyId);
            }
        });
    }
}
