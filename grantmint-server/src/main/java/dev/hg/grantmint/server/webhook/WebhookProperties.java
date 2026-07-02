package dev.hg.grantmint.server.webhook;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the webhook adapters under {@code grantmint.webhooks}. An adapter whose
 * {@code enabled} flag is off (or absent) is never created and its provider path 404s — enabling a
 * provider is "set the secret + flip enabled", nothing more. See
 * docs/features/WEBHOOK_INTEGRATION.md.
 */
@ConfigurationProperties(prefix = "grantmint.webhooks")
public class WebhookProperties {

    private final Stripe stripe = new Stripe();

    public Stripe getStripe() {
        return stripe;
    }

    /** The Stripe reference adapter's settings. */
    public static class Stripe {

        /** Master switch; the adapter bean is created only when true AND a secret is set. */
        private boolean enabled = false;

        /** The endpoint signing secret from the Stripe dashboard ({@code whsec_…}). Never logged. */
        private String signingSecret;

        /** Replay window: events whose signature timestamp is older than this are rejected. */
        private long toleranceSeconds = 300;

        /** Provider price id → Grantmint policy code to issue from. */
        private Map<String, String> policyMap = new LinkedHashMap<>();

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getSigningSecret() {
            return signingSecret;
        }

        public void setSigningSecret(String signingSecret) {
            this.signingSecret = signingSecret;
        }

        public long getToleranceSeconds() {
            return toleranceSeconds;
        }

        public void setToleranceSeconds(long toleranceSeconds) {
            this.toleranceSeconds = toleranceSeconds;
        }

        public Map<String, String> getPolicyMap() {
            return policyMap;
        }

        public void setPolicyMap(Map<String, String> policyMap) {
            this.policyMap = policyMap;
        }
    }
}
