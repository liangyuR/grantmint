package dev.hg.grantmint.client;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the Grantmint client under {@code grantmint.client}. The {@code public-key} is
 * configuration you control, not a secret — the entire offline model depends on it being baked into
 * the app; the {@code validation-key} is semi-public (rate-limited, cannot mint or revoke). See
 * docs/features/CLIENT_SDK.md for every property.
 */
@ConfigurationProperties(prefix = "grantmint.client")
public class GrantmintClientProperties {

    /** How the validator combines offline verification with the online layer. */
    public enum Mode {
        /** Signature + expiry against the embedded key only; works air-gapped. */
        OFFLINE,
        /** Server validation only. */
        ONLINE,
        /** Offline as the fast baseline, online for revocation/seat truth (default). */
        HYBRID
    }

    private boolean enabled = true;

    /** Product key registered in Grantmint; verified against the token's {@code prd} claim. */
    private String product;

    /** Grantmint server base URL — required for online/hybrid, ignored for offline. */
    private String serverUrl;

    /** {@code gm_val_…} validation key — semi-public, shipped with the app. */
    private String validationKey;

    /** The full signed token this instance runs under ({@code header.payload.signature}). */
    private String licenseToken;

    /** Short key id, e.g. {@code K7P2-9QXM-4T1A} — the online identifier. */
    private String keyId;

    /** Standard base64 of the 32-byte raw Ed25519 public key. */
    private String publicKey;

    private Mode mode = Mode.HYBRID;

    /** When the online check is unreachable: deny ({@code false}, the safe default) or allow. */
    private boolean failOpen = false;

    private final Cache cache = new Cache();
    private final Online online = new Online();

    /** Client-side caching of online validation results. */
    public static class Cache {
        /** How long an online validation result is trusted before re-checking. */
        private Duration ttl = Duration.ofMinutes(15);

        public Duration getTtl() {
            return ttl;
        }

        public void setTtl(Duration ttl) {
            this.ttl = ttl;
        }
    }

    /** Online transport tuning. */
    public static class Online {
        private Duration heartbeatInterval = Duration.ofHours(12);
        private Duration connectTimeout = Duration.ofSeconds(3);
        private Duration readTimeout = Duration.ofSeconds(5);

        public Duration getHeartbeatInterval() {
            return heartbeatInterval;
        }

        public void setHeartbeatInterval(Duration heartbeatInterval) {
            this.heartbeatInterval = heartbeatInterval;
        }

        public Duration getConnectTimeout() {
            return connectTimeout;
        }

        public void setConnectTimeout(Duration connectTimeout) {
            this.connectTimeout = connectTimeout;
        }

        public Duration getReadTimeout() {
            return readTimeout;
        }

        public void setReadTimeout(Duration readTimeout) {
            this.readTimeout = readTimeout;
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getProduct() {
        return product;
    }

    public void setProduct(String product) {
        this.product = product;
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(String serverUrl) {
        this.serverUrl = serverUrl;
    }

    public String getValidationKey() {
        return validationKey;
    }

    public void setValidationKey(String validationKey) {
        this.validationKey = validationKey;
    }

    public String getLicenseToken() {
        return licenseToken;
    }

    public void setLicenseToken(String licenseToken) {
        this.licenseToken = licenseToken;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public Mode getMode() {
        return mode;
    }

    public void setMode(Mode mode) {
        this.mode = mode;
    }

    public boolean isFailOpen() {
        return failOpen;
    }

    public void setFailOpen(boolean failOpen) {
        this.failOpen = failOpen;
    }

    public Cache getCache() {
        return cache;
    }

    public Online getOnline() {
        return online;
    }
}
