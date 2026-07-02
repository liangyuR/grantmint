package dev.hg.grantmint.server.webhook;

import dev.hg.grantmint.core.license.LicenseEvent;
import dev.hg.grantmint.core.license.LicenseState;
import dev.hg.grantmint.core.license.LicenseStateMachine;
import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.issuance.IssuanceCommand;
import dev.hg.grantmint.server.issuance.IssuanceService;
import dev.hg.grantmint.server.lifecycle.LicenseLifecycleService;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.PolicyRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Applies a webhook's {@link LicenseAction}s — issue / suspend / reinstate / expire, never money.
 * The design goal is <b>convergence, not strictness</b>: providers deliver at-least-once and out of
 * order, so an action whose effect already holds (reinstating an already-active license, expiring
 * an already-expired one, issuing for a subscription that already has a license) is a logged no-op,
 * not an error. Returning an error would only make the provider retry a request that can never
 * change anything. Genuine mapping problems (unknown policy code, no license for an externalRef)
 * are logged at WARN so operators notice — see the failure-modes table in
 * docs/features/WEBHOOK_INTEGRATION.md.
 */
@Service
public class LicenseActionExecutor {

    private static final Logger log = LoggerFactory.getLogger(LicenseActionExecutor.class);

    private final LicenseStateMachine machine = new LicenseStateMachine();
    private final PolicyRepository policies;
    private final LicenseRepository licenses;
    private final IssuanceService issuance;
    private final LicenseLifecycleService lifecycle;

    public LicenseActionExecutor(
            PolicyRepository policies,
            LicenseRepository licenses,
            IssuanceService issuance,
            LicenseLifecycleService lifecycle) {
        this.policies = policies;
        this.licenses = licenses;
        this.issuance = issuance;
        this.lifecycle = lifecycle;
    }

    /**
     * Apply all actions, joining the caller's ingest transaction so the idempotency ledger row and
     * the licensing effects commit or roll back together.
     *
     * @param actor the audit actor, e.g. {@code webhook:stripe}
     * @return the id of the license created or changed, if exactly one was (for the ledger row)
     */
    public Outcome apply(List<LicenseAction> actions, String actor) {
        boolean effect = false;
        UUID resultingLicenseId = null;
        for (LicenseAction action : actions) {
            Optional<UUID> touched = applyOne(action, actor);
            if (touched.isPresent()) {
                effect = true;
                resultingLicenseId = touched.get();
            }
        }
        return new Outcome(effect, resultingLicenseId);
    }

    private Optional<UUID> applyOne(LicenseAction action, String actor) {
        return switch (action) {
            case LicenseAction.IssueLicense issue -> issue(issue, actor);
            case LicenseAction.SuspendLicense suspend -> onEach(
                    suspend.externalRef(),
                    LicenseEvent.SUSPEND,
                    license -> lifecycle.suspend(
                            license.getKeyId(), null, suspend.reason(), actor, AuditActorType.WEBHOOK, null));
            case LicenseAction.ReinstateLicense reinstate -> onEach(
                    reinstate.externalRef(),
                    LicenseEvent.REINSTATE,
                    license -> lifecycle.reinstate(license.getKeyId(), null, actor, AuditActorType.WEBHOOK, null));
            case LicenseAction.ExpireLicense expire -> onEach(
                    expire.externalRef(),
                    LicenseEvent.EXPIRE,
                    license ->
                            lifecycle.expire(license.getKeyId(), null, "webhook", actor, AuditActorType.WEBHOOK, null));
            case LicenseAction.Ignore ignore -> {
                // Mapping-config-missing arrives here; it must be loud, not silent — a customer may
                // have paid without a license being minted (see WEBHOOK_INTEGRATION.md).
                log.warn("Webhook action ignored: {}", ignore.reason());
                yield Optional.empty();
            }
        };
    }

    private Optional<UUID> issue(LicenseAction.IssueLicense action, String actor) {
        // At-least-once + multiple issue-shaped events (checkout completed AND subscription created)
        // can arrive with distinct event ids for one subscription: the externalRef, not the event
        // id, is the issue-level idempotency key.
        if (action.externalRef() != null
                && !action.externalRef().isBlank()
                && !licenses.findByExternalRef(action.externalRef()).isEmpty()) {
            log.info("Webhook issue skipped: a license already exists for externalRef");
            return Optional.empty();
        }
        List<Policy> matches = policies.findByCode(action.policyKey());
        if (matches.size() != 1) {
            // Unknown or ambiguous policy code: an operator configuration problem, never a guess.
            log.warn(
                    "Webhook issue skipped: policy code '{}' resolves to {} policies — fix the policy-map",
                    action.policyKey(),
                    matches.size());
            return Optional.empty();
        }
        Policy policy = matches.get(0);
        String holderName = orFallback(action.holder().name(), action.holder().email());
        String holderEmail = action.holder().email();
        if (holderEmail == null || holderEmail.isBlank()) {
            log.warn(
                    "Webhook issue skipped: provider event carries no holder email for policy '{}'",
                    action.policyKey());
            return Optional.empty();
        }
        var issued = issuance.issue(
                new IssuanceCommand(
                        policy.getProduct().getId(),
                        policy.getId(),
                        holderName,
                        holderEmail,
                        null,
                        null,
                        action.externalRef(),
                        actor,
                        null),
                AuditActorType.WEBHOOK);
        License license = licenses.findByKeyId(issued.keyId()).orElseThrow();
        return Optional.of(license.getId());
    }

    /**
     * Run a lifecycle mutation over every license tied to the externalRef, skipping any license the
     * event is not legal for — reinstate on a non-suspended license, expire on an expired one — as
     * a logged no-op: the desired end state effectively already holds. The legality probe uses the
     * core state machine's {@code permits} rather than catch-and-ignore, because an exception that
     * crosses the lifecycle service's transactional proxy would mark the shared ingest transaction
     * rollback-only even when caught. A status change racing between probe and apply still throws
     * and rolls the event back to a 500 — the provider's retry then converges.
     */
    private Optional<UUID> onEach(
            String externalRef, LicenseEvent event, java.util.function.Consumer<License> mutation) {
        if (externalRef == null || externalRef.isBlank()) {
            log.warn("Webhook {} skipped: event carries no subscription/customer reference", event);
            return Optional.empty();
        }
        List<License> matches = licenses.findByExternalRef(externalRef);
        if (matches.isEmpty()) {
            log.warn("Webhook {} skipped: no license for externalRef", event);
            return Optional.empty();
        }
        UUID last = null;
        for (License license : matches) {
            if (!machine.permits(LicenseState.valueOf(license.getStatus().name()), event)) {
                log.info(
                        "Webhook {} no-op for license {}: already {}",
                        event,
                        license.getKeyId(),
                        license.getStatus().wire());
                continue;
            }
            mutation.accept(license);
            last = license.getId();
        }
        return Optional.ofNullable(last);
    }

    private static String orFallback(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    /** Whether any license was actually created/changed, and (if exactly one) which. */
    public record Outcome(boolean effect, UUID resultingLicenseId) {}
}
