package dev.hg.grantmint.server.webhook;

import dev.hg.grantmint.server.webhook.stripe.StripeWebhookAdapter;
import java.time.Clock;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the webhook adapters by configuration: the Stripe reference adapter exists only when
 * {@code grantmint.webhooks.stripe.enabled=true} (and its signing secret is set — the adapter
 * refuses a blank secret at construction). The registry collects <em>every</em>
 * {@link PaymentWebhookAdapter} bean on the context, so adding a provider is "define a bean +
 * configure it"; an unconfigured provider's path simply 404s. See
 * docs/features/WEBHOOK_INTEGRATION.md.
 */
@Configuration
@EnableConfigurationProperties(WebhookProperties.class)
public class WebhookConfiguration {

    @Bean
    @ConditionalOnProperty(prefix = "grantmint.webhooks.stripe", name = "enabled", havingValue = "true")
    StripeWebhookAdapter stripeWebhookAdapter(WebhookProperties properties, Clock clock) {
        return new StripeWebhookAdapter(properties.getStripe(), clock);
    }

    @Bean
    WebhookAdapterRegistry webhookAdapterRegistry(List<PaymentWebhookAdapter> adapters) {
        return new WebhookAdapterRegistry(adapters);
    }
}
