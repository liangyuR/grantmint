package dev.hg.grantmint.server.webhook;

import java.util.List;

/**
 * A payment-provider webhook adapter (Strategy). Implementations translate a provider's webhook
 * into Grantmint licensing actions. They MUST NOT process payments, move money, or call back into
 * the provider's billing APIs — the provider handles the money, Grantmint handles the licensing.
 * See docs/features/WEBHOOK_INTEGRATION.md.
 */
public interface PaymentWebhookAdapter {

    /** Provider id; also the URL suffix: {@code POST /webhooks/{provider}}. E.g. {@code stripe}. */
    String provider();

    /**
     * Verify the request is authentically from the provider — a signature over the RAW body bytes,
     * with replay protection. Throw to reject the request with HTTP 400. Always called before
     * {@link #parse}: never act on unverified input.
     */
    void verify(WebhookRequest request) throws WebhookSignatureException;

    /** Parse the verified raw body into a provider-neutral event. Called only after verify(). */
    WebhookEvent parse(WebhookRequest request);

    /**
     * Map a verified event to zero or more licensing actions. An EMPTY list (or only
     * {@link LicenseAction.Ignore}) means "recognized but intentionally ignored" → HTTP 200 no-op,
     * so the provider never retries an event Grantmint doesn't care about.
     */
    List<LicenseAction> toActions(WebhookEvent event);

    /** Stable, provider-assigned event id used for idempotency (e.g. Stripe {@code evt_…}). */
    String eventId(WebhookEvent event);
}
