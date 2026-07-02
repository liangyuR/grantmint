package dev.hg.grantmint.server.webhook;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Routes an incoming {@code /webhooks/{provider}} request to the adapter for that provider. Built
 * once over every {@link PaymentWebhookAdapter} bean on the context — a provider whose adapter is
 * not configured (no bean) simply is not here, and its path 404s.
 */
public class WebhookAdapterRegistry {

    private final Map<String, PaymentWebhookAdapter> byProvider = new HashMap<>();

    public WebhookAdapterRegistry(List<PaymentWebhookAdapter> adapters) {
        for (PaymentWebhookAdapter adapter : adapters) {
            // Locale.ROOT: provider ids are ASCII identifiers, never locale-folded.
            byProvider.put(adapter.provider().toLowerCase(Locale.ROOT), adapter);
        }
    }

    public Optional<PaymentWebhookAdapter> find(String provider) {
        return Optional.ofNullable(byProvider.get(provider.toLowerCase(Locale.ROOT)));
    }
}
