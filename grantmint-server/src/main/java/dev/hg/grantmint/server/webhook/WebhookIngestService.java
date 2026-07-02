package dev.hg.grantmint.server.webhook;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The transactional heart of webhook intake: ledger insert + licensing effects in ONE transaction.
 *
 * <p>The idempotency ledger row ({@code webhook_events}, {@code UNIQUE(provider,
 * provider_event_id)}) is checked and inserted <em>first</em>; a re-delivered event id is answered
 * as a no-op success. Because the insert and the {@link LicenseActionExecutor} effects share a
 * transaction, a failure while applying actions rolls the ledger row back too — so the provider's
 * retry of a transiently-failed event is <em>not</em> mistaken for a duplicate and gets processed.
 * The rare same-instant double delivery is settled by the unique index itself: the check-then-insert
 * race loser fails at flush, the transaction rolls back to a 500, and the provider's retry then sees
 * the committed duplicate. (Catching the violation in-transaction is deliberately avoided — a failed
 * flush poisons the transaction and would turn the commit into an UnexpectedRollbackException.) The
 * database, not application logic, is the idempotency invariant.
 */
@Service
public class WebhookIngestService {

    private final dev.hg.grantmint.server.repo.WebhookEventRepository events;
    private final LicenseActionExecutor executor;
    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper();

    public WebhookIngestService(
            dev.hg.grantmint.server.repo.WebhookEventRepository events, LicenseActionExecutor executor, Clock clock) {
        this.events = events;
        this.executor = executor;
        this.clock = clock;
    }

    /**
     * Record and apply one verified event.
     *
     * @return DUPLICATE for a re-delivered event id (no-op), PROCESSED when any licensing effect
     *     was applied, IGNORED when the event was recognized but had no effect
     */
    @Transactional
    public Result ingest(PaymentWebhookAdapter adapter, WebhookRequest request, WebhookEvent event) {
        String provider = adapter.provider().toLowerCase(Locale.ROOT);
        String eventId = adapter.eventId(event);

        if (events.findByProviderAndProviderEventId(provider, eventId).isPresent()) {
            return Result.DUPLICATE;
        }
        dev.hg.grantmint.server.domain.WebhookEvent ledger = new dev.hg.grantmint.server.domain.WebhookEvent();
        ledger.setProvider(provider);
        ledger.setProviderEventId(eventId);
        ledger.setEventType(event.type());
        ledger.setSignatureValid(true); // only verified requests reach ingest
        ledger.setPayload(payloadOf(request));
        // A same-instant racer may still violate the unique index here — that propagates as a 500
        // and the provider's retry lands on the duplicate check above. See the class javadoc.
        events.saveAndFlush(ledger);

        List<LicenseAction> actions = adapter.toActions(event);
        LicenseActionExecutor.Outcome outcome = executor.apply(actions, "webhook:" + provider);

        ledger.setStatus(outcome.effect() ? "processed" : "ignored");
        ledger.setProcessedAt(OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));
        ledger.setResultingLicenseId(outcome.resultingLicenseId());
        return outcome.effect() ? Result.PROCESSED : Result.IGNORED;
    }

    /** The raw verified body as the ledger's jsonb payload; a non-object body is wrapped. */
    private Map<String, Object> payloadOf(WebhookRequest request) {
        try {
            return mapper.readValue(request.rawBody(), new TypeReference<Map<String, Object>>() {});
        } catch (Exception nonObjectBody) {
            return Map.of("raw", new String(request.rawBody(), java.nio.charset.StandardCharsets.UTF_8));
        }
    }

    public enum Result {
        PROCESSED,
        IGNORED,
        DUPLICATE
    }
}
