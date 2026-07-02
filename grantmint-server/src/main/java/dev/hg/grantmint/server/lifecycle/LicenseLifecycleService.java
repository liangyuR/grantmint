package dev.hg.grantmint.server.lifecycle;

import dev.hg.grantmint.core.license.IllegalLicenseTransitionException;
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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * The admin lifecycle actions — suspend, reinstate, revoke — driving the {@code grantmint-core}
 * {@link LicenseStateMachine} and persisting the result. Every mutation runs under the same
 * pessimistic license-row lock the activation path takes (so a lifecycle change and a seat change
 * serialize), emits an audit event, and evicts the validation-cache entry <em>after commit</em> —
 * these are the eviction call sites the M5 cache promised, closing the revocation-latency window
 * the instant the transaction lands instead of waiting out the TTL.
 *
 * <p>Illegal moves (reinstating a revoked license, suspending one never activated) surface as
 * {@link IllegalLicenseTransitionException} → 409 {@code invalid_state_transition}; the state
 * machine, not this service, owns legality. See docs/features/LICENSE_LIFECYCLE.md.
 */
@Service
public class LicenseLifecycleService {

    private final LicenseRepository licenses;
    private final ValidationCache cache;
    private final AuditService audit;
    private final Clock clock;
    private final LicenseStateMachine machine = new LicenseStateMachine();

    public LicenseLifecycleService(LicenseRepository licenses, ValidationCache cache, AuditService audit, Clock clock) {
        this.licenses = licenses;
        this.cache = cache;
        this.audit = audit;
        this.clock = clock;
    }

    /** ACTIVE → SUSPENDED (recoverable pause, e.g. failed payment). */
    @Transactional
    public LifecycleResult suspend(
            String keyId, UUID requesterProductId, String reason, String actor, AuditActorType actorType, String ip) {
        return apply(keyId, requesterProductId, LicenseEvent.SUSPEND, reason, actor, actorType, ip);
    }

    /** SUSPENDED → ACTIVE (recovery; online checks pass again immediately). */
    @Transactional
    public LifecycleResult reinstate(
            String keyId, UUID requesterProductId, String actor, AuditActorType actorType, String ip) {
        return apply(keyId, requesterProductId, LicenseEvent.REINSTATE, null, actor, actorType, ip);
    }

    /** Any non-revoked state → REVOKED. Terminal — disputes get a new license, never an un-revoke. */
    @Transactional
    public LifecycleResult revoke(
            String keyId, UUID requesterProductId, String reason, String actor, AuditActorType actorType, String ip) {
        return apply(keyId, requesterProductId, LicenseEvent.REVOKE, reason, actor, actorType, ip);
    }

    /**
     * CREATED/ACTIVE/SUSPENDED → EXPIRED. Driven by the expiry sweep's siblings — the webhook layer
     * (subscription cancelled/refunded) — rather than an admin endpoint; the sweep job itself flips
     * rows directly on its own schedule.
     */
    @Transactional
    public LifecycleResult expire(
            String keyId, UUID requesterProductId, String reason, String actor, AuditActorType actorType, String ip) {
        return apply(keyId, requesterProductId, LicenseEvent.EXPIRE, reason, actor, actorType, ip);
    }

    private LifecycleResult apply(
            String keyId,
            UUID requesterProductId,
            LicenseEvent event,
            String reason,
            String actor,
            AuditActorType actorType,
            String ip) {
        // Same lock as the activation path: lifecycle and seat changes serialize on the row.
        License license = licenses.findByKeyIdForUpdate(keyId)
                .orElseThrow(() -> new NoSuchElementException("License not found: " + keyId));
        // keyId-addressed resources 404 across products (like validate/activate): whether a license
        // exists at all is customer data, unlike the caller-supplied policy ids of the issue path.
        if (requesterProductId != null
                && !requesterProductId.equals(license.getProduct().getId())) {
            throw new NoSuchElementException("License not found: " + keyId);
        }

        LicenseState next = machine.apply(stateOf(license.getStatus()), event);
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        switch (event) {
            case SUSPEND -> {
                license.setStatus(LicenseStatus.SUSPENDED);
                license.setSuspendedAt(now);
            }
            case REINSTATE -> {
                license.setStatus(LicenseStatus.ACTIVE);
                license.setSuspendedAt(null);
            }
            case REVOKE -> {
                license.setStatus(LicenseStatus.REVOKED);
                license.setRevokedAt(now);
                license.setRevocationReason(reason);
            }
            case EXPIRE -> license.setStatus(LicenseStatus.EXPIRED);
            default -> throw new IllegalStateException("Unsupported admin lifecycle event: " + event);
        }

        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("key_id", license.getKeyId());
        detail.put("to_status", next.name().toLowerCase(java.util.Locale.ROOT));
        if (reason != null && !reason.isBlank()) {
            detail.put("reason", reason);
        }
        audit.record(
                actor,
                actorType,
                auditActionOf(event),
                "license",
                license.getId().toString(),
                detail,
                ip);
        evictAfterCommit(license.getKeyId());
        return new LifecycleResult(
                license.getId(),
                license.getKeyId(),
                license.getStatus().wire(),
                license.getSuspendedAt(),
                license.getRevokedAt(),
                reason);
    }

    /** Map the persisted status onto the core state machine's vocabulary (same five names). */
    private static LicenseState stateOf(LicenseStatus status) {
        return LicenseState.valueOf(status.name());
    }

    private static String auditActionOf(LicenseEvent event) {
        return switch (event) {
            case SUSPEND -> "license.suspended";
            case REINSTATE -> "license.reinstated";
            case REVOKE -> "license.revoked";
            case EXPIRE -> "license.expired";
            default -> throw new IllegalStateException("Unsupported admin lifecycle event: " + event);
        };
    }

    /**
     * Evict only after commit — evicting inline would let a concurrent validate re-cache the
     * pre-commit row and pin the stale status for a full TTL.
     */
    private void evictAfterCommit(String keyId) {
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                cache.evict(keyId);
            }
        });
    }

    /** Outcome of a lifecycle action: the license's new persisted state and stamps. */
    public record LifecycleResult(
            UUID id,
            String keyId,
            String status,
            OffsetDateTime suspendedAt,
            OffsetDateTime revokedAt,
            String reason) {}
}
