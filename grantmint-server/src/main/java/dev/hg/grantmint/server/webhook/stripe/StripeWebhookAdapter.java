package dev.hg.grantmint.server.webhook.stripe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.grantmint.server.webhook.LicenseAction;
import dev.hg.grantmint.server.webhook.LicenseAction.ExpireLicense;
import dev.hg.grantmint.server.webhook.LicenseAction.Holder;
import dev.hg.grantmint.server.webhook.LicenseAction.Ignore;
import dev.hg.grantmint.server.webhook.LicenseAction.IssueLicense;
import dev.hg.grantmint.server.webhook.LicenseAction.ReinstateLicense;
import dev.hg.grantmint.server.webhook.LicenseAction.SuspendLicense;
import dev.hg.grantmint.server.webhook.PaymentWebhookAdapter;
import dev.hg.grantmint.server.webhook.WebhookEvent;
import dev.hg.grantmint.server.webhook.WebhookProperties;
import dev.hg.grantmint.server.webhook.WebhookRequest;
import dev.hg.grantmint.server.webhook.WebhookSignatureException;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * The Stripe reference adapter: HMAC signature verification (see {@link StripeSignatureVerifier})
 * plus the event → licensing-action mapping table of docs/features/WEBHOOK_INTEGRATION.md. It never
 * charges, refunds, or calls back into Stripe — {@code charge.refunded} does not refund anyone here
 * (Stripe already did); it only expires the license in response.
 */
public class StripeWebhookAdapter implements PaymentWebhookAdapter {

    private final StripeSignatureVerifier verifier;
    private final Map<String, String> policyMap;
    private final ObjectMapper mapper = new ObjectMapper();

    public StripeWebhookAdapter(WebhookProperties.Stripe config, Clock clock) {
        this.verifier = new StripeSignatureVerifier(
                config.getSigningSecret(), Duration.ofSeconds(config.getToleranceSeconds()), clock);
        this.policyMap = Map.copyOf(config.getPolicyMap());
    }

    @Override
    public String provider() {
        return "stripe";
    }

    @Override
    public void verify(WebhookRequest request) throws WebhookSignatureException {
        verifier.verify(request); // signature + replay window, over the raw bytes
    }

    @Override
    public WebhookEvent parse(WebhookRequest request) {
        try {
            JsonNode root = mapper.readTree(request.rawBody());
            return new WebhookEvent(
                    root.path("id").asText(),
                    root.path("type").asText(),
                    root.path("data").path("object"));
        } catch (Exception e) {
            throw new IllegalArgumentException("unparseable stripe event", e);
        }
    }

    @Override
    public String eventId(WebhookEvent event) {
        return event.id(); // "evt_…"
    }

    @Override
    public List<LicenseAction> toActions(WebhookEvent event) {
        JsonNode obj = event.data();
        return switch (event.type()) {
            case "checkout.session.completed", "customer.subscription.created" -> {
                String priceId = obj.path("items")
                        .path("data")
                        .path(0)
                        .path("price")
                        .path("id")
                        .asText(null);
                String policy = policyMap.get(priceId);
                if (policy == null) {
                    // Mapping-config-missing: a paying customer with no mapped policy. Surfaced as
                    // an explicit Ignore (200, so Stripe stops retrying) that the executor logs and
                    // audits loudly — see the failure-modes table in WEBHOOK_INTEGRATION.md.
                    yield List.of(new Ignore("no policy mapped for price " + priceId));
                }
                Holder holder = new Holder(
                        obj.path("customer_details").path("name").asText(""),
                        obj.path("customer_details").path("email").asText(""));
                yield List.of(new IssueLicense(policy, holder, externalRef(obj)));
            }
            case "invoice.payment_failed" -> List.of(new SuspendLicense(externalRef(obj), "payment_failed"));
            case "invoice.paid", "invoice.payment_succeeded" -> List.of(new ReinstateLicense(externalRef(obj)));
            case "customer.subscription.deleted" -> List.of(new ExpireLicense(externalRef(obj)));
            case "charge.refunded" -> List.of(new ExpireLicense(externalRef(obj)));
            default -> List.of(new Ignore(event.type())); // recognized-but-ignored → 200
        };
    }

    /** Subscription id when present, else customer id — the link between Stripe and the license. */
    private static String externalRef(JsonNode obj) {
        String subscription = obj.path("subscription").asText("");
        return subscription.isEmpty() ? obj.path("customer").asText("") : subscription;
    }
}
