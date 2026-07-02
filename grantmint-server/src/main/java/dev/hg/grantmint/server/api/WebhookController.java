package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.webhook.PaymentWebhookAdapter;
import dev.hg.grantmint.server.webhook.WebhookAdapterRegistry;
import dev.hg.grantmint.server.webhook.WebhookEvent;
import dev.hg.grantmint.server.webhook.WebhookIngestService;
import dev.hg.grantmint.server.webhook.WebhookRequest;
import dev.hg.grantmint.server.webhook.WebhookSignatureException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Webhook ingestion — {@code POST /webhooks/{provider}}. The only license-mutating surface with no
 * Grantmint API key: it is authenticated by the <b>provider's signature over the raw body bytes</b>
 * instead (which is why the body binds as {@code byte[]} — a parse/re-serialize cycle would change
 * the bytes and break the HMAC). Deliberately outside every Spring Security chain matcher.
 *
 * <p>Response contract (docs/features/WEBHOOK_INTEGRATION.md failure modes): 2xx for everything
 * successfully received and recognized — including duplicates and ignored events — so the provider
 * never retries a request that can never change anything; 400 only for signature failures; 404 for
 * a provider with no configured adapter; a genuine internal failure propagates as 500 so the
 * provider retries (safe: the ledger row rolls back with the failed transaction).
 */
@RestController
@RequestMapping("/webhooks")
@Tag(name = "Webhooks", description = "Payment-provider webhook ingestion (signature-authenticated).")
public class WebhookController {

    private static final Logger log = LoggerFactory.getLogger(WebhookController.class);

    private final WebhookAdapterRegistry registry;
    private final WebhookIngestService ingest;

    public WebhookController(WebhookAdapterRegistry registry, WebhookIngestService ingest) {
        this.registry = registry;
        this.ingest = ingest;
    }

    @PostMapping("/{provider}")
    @Operation(
            summary = "Receive a payment-provider webhook",
            description = "Verifies the provider signature over the raw body, records the event id for "
                    + "idempotency, and applies the mapped licensing actions (issue / suspend / reinstate / "
                    + "expire). Never charges, refunds, or moves money.")
    ResponseEntity<Map<String, String>> receive(
            @PathVariable String provider, @RequestBody byte[] rawBody, HttpServletRequest httpRequest) {
        PaymentWebhookAdapter adapter = registry.find(provider).orElse(null);
        if (adapter == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("status", "unknown provider"));
        }
        WebhookRequest request = new WebhookRequest(rawBody, headersOf(httpRequest));

        // 1) Signature first — never parse, persist, or act on unverified input.
        try {
            adapter.verify(request);
        } catch (WebhookSignatureException rejected) {
            // Reason goes to the log only; the response stays opaque to a probing forger.
            log.warn("Rejected {} webhook: {}", provider, rejected.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("status", "invalid signature"));
        }

        WebhookEvent event = adapter.parse(request);

        // 2+3) Ledger insert + actions in one transaction (see WebhookIngestService).
        WebhookIngestService.Result result = ingest.ingest(adapter, request, event);
        return switch (result) {
            case DUPLICATE -> ResponseEntity.ok(Map.of("status", "duplicate ignored"));
            case IGNORED -> ResponseEntity.ok(Map.of("status", "ignored"));
            case PROCESSED -> ResponseEntity.ok(Map.of("status", "processed"));
        };
    }

    private static Map<String, String> headersOf(HttpServletRequest request) {
        Map<String, String> headers = new LinkedHashMap<>();
        for (String name : Collections.list(request.getHeaderNames())) {
            headers.put(name, request.getHeader(name));
        }
        return headers;
    }
}
