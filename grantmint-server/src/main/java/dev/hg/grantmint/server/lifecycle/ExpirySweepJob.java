package dev.hg.grantmint.server.lifecycle;

import dev.hg.grantmint.core.license.LicenseEvent;
import dev.hg.grantmint.core.license.LicenseState;
import dev.hg.grantmint.core.license.LicenseStateMachine;
import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.validation.ValidationCache;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Flips {@code active}/{@code suspended} licenses to {@code expired} once their grace window has
 * elapsed — the background half of the state machine's {@link LicenseEvent#EXPIRE} edge (the other
 * half, an admin-driven event, doesn't exist; expiry only ever happens here). See
 * docs/features/LICENSE_LIFECYCLE.md ("The background expiry-sweep job").
 *
 * <p><b>Why the query and the grace filter are split.</b> {@link LicenseRepository#findExpiryCandidates}
 * takes a single cutoff (now) and returns every non-terminal license whose {@code expires_at} is
 * already in the past — deliberately over-inclusive, because policies carry <em>different</em>
 * {@code grace_period_days} and a single SQL predicate can't apply a per-row grace window without a
 * join the query intentionally avoids. This job applies the per-license grace
 * ({@code expiresAt + policy.gracePeriodDays}) in Java after loading each candidate's (lazy) policy,
 * so a license just past its raw expiry but still inside its grace period is correctly left alone.
 *
 * <p>Runs as a single {@code @Scheduled} + {@code @Transactional} method: Spring's scheduling proxy
 * and its transaction proxy both wrap the same public method, so no self-invocation pitfall applies
 * here (unlike a private helper called from within the same bean).
 */
@Component
public class ExpirySweepJob {

    private static final Logger log = LoggerFactory.getLogger(ExpirySweepJob.class);

    /** Non-terminal statuses the state machine allows EXPIRE from that the sweep also targets. */
    private static final EnumSet<LicenseStatus> SWEEPABLE_STATUSES =
            EnumSet.of(LicenseStatus.ACTIVE, LicenseStatus.SUSPENDED);

    private final LicenseRepository licenses;
    private final ValidationCache cache;
    private final AuditService audit;
    private final Clock clock;
    private final LicenseStateMachine machine = new LicenseStateMachine();

    public ExpirySweepJob(LicenseRepository licenses, ValidationCache cache, AuditService audit, Clock clock) {
        this.licenses = licenses;
        this.cache = cache;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * Sweep entry point, invoked on the configured interval (default every 5 minutes; see
     * {@code grantmint.lifecycle.expiry-sweep-interval}).
     */
    @Scheduled(fixedDelayString = "${grantmint.lifecycle.expiry-sweep-interval:PT5M}")
    @Transactional
    public void sweep() {
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        List<License> candidates = licenses.findExpiryCandidates(SWEEPABLE_STATUSES, now);
        int expiredCount = 0;
        for (License license : candidates) {
            // Lazy-loaded inside this transaction: each candidate may belong to a different policy
            // with a different grace window.
            int graceDays = license.getPolicy().getGracePeriodDays();
            if (license.getExpiresAt().plusDays(graceDays).isAfter(now)) {
                continue; // still within grace — leave it alone
            }
            expireOne(license, now);
            expiredCount++;
        }
        if (expiredCount > 0) {
            log.info("Expiry sweep flipped {} license(s) to expired", expiredCount);
        }
    }

    private void expireOne(License license, OffsetDateTime now) {
        // The state machine only sees the two states the query fetched (ACTIVE, SUSPENDED); both are
        // legal EXPIRE sources, so this never throws in practice — the call is kept to route through
        // the same authority every other lifecycle mutation does.
        LicenseState next =
                machine.apply(LicenseState.valueOf(license.getStatus().name()), LicenseEvent.EXPIRE);
        license.setStatus(LicenseStatus.EXPIRED);

        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("key_id", license.getKeyId());
        detail.put("to_status", next.name().toLowerCase(Locale.ROOT));
        audit.record(
                "system",
                AuditActorType.SYSTEM,
                "license.expired",
                "license",
                license.getId().toString(),
                detail);
        evictAfterCommit(license.getKeyId());
    }

    /**
     * Evict only after commit — evicting inline would let a concurrent validate re-cache the
     * pre-commit (still-active) row and pin the stale status for a full TTL. Same pattern as
     * {@link dev.hg.grantmint.server.lifecycle.LicenseLifecycleService}.
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
