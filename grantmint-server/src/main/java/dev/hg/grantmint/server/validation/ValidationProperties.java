package dev.hg.grantmint.server.validation;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Tunables for the online validation path. The cache TTL is the single most important knob: a cached
 * {@code ACTIVE} snapshot is served without re-reading the database, so the TTL is also the
 * <strong>maximum revocation latency</strong> — the longest a revoked or suspended license can keep
 * passing online validation before the stale entry expires (an explicit evict, wired by the M6/M7
 * mutation paths, shortens this to zero). See docs/reference/PERFORMANCE_OPTIMIZATION.md and
 * docs/architecture/ARCHITECTURE.md (validation flow, caching).
 */
@ConfigurationProperties("grantmint.validation")
public class ValidationProperties {

    private final Cache cache = new Cache();
    private final RateLimit rateLimit = new RateLimit();

    public Cache getCache() {
        return cache;
    }

    public RateLimit getRateLimit() {
        return rateLimit;
    }

    /** Caffeine validation-snapshot cache settings. */
    public static class Cache {

        /** Snapshot freshness window — also the revocation-latency ceiling. */
        private Duration ttl = Duration.ofSeconds(60);

        /** Upper bound on cached licenses; least-recently-used entries are evicted past it. */
        private long maximumSize = 50_000;

        public Duration getTtl() {
            return ttl;
        }

        public void setTtl(Duration ttl) {
            this.ttl = ttl;
        }

        public long getMaximumSize() {
            return maximumSize;
        }

        public void setMaximumSize(long maximumSize) {
            this.maximumSize = maximumSize;
        }
    }

    /**
     * Hot-path rate limits. Each dimension is a token bucket: {@code capacity} permits a burst, the
     * {@code window} sets the sustained refill rate ({@code capacity} tokens per window). The per-IP
     * allowance is higher because one IP legitimately fronts many distinct license keys.
     */
    public static class RateLimit {

        private boolean enabled = true;
        private long perKeyCapacity = 60;
        private Duration perKeyWindow = Duration.ofMinutes(1);
        private long perIpCapacity = 600;
        private Duration perIpWindow = Duration.ofMinutes(1);

        /**
         * Reverse proxies whose {@code X-Forwarded-For} header may be trusted to carry the real client
         * IP, as a list of CIDRs (or bare IPs). Empty by default — the socket peer is used and any
         * forwarded header is ignored, so a direct client cannot spoof its source IP. Set this to the
         * load balancer / ingress addresses once the topology is known. See {@link ClientIpResolver}.
         */
        private List<String> trustedProxies = List.of();

        public boolean isEnabled() {
            return enabled;
        }

        public List<String> getTrustedProxies() {
            return trustedProxies;
        }

        public void setTrustedProxies(List<String> trustedProxies) {
            this.trustedProxies = trustedProxies == null ? List.of() : List.copyOf(trustedProxies);
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public long getPerKeyCapacity() {
            return perKeyCapacity;
        }

        public void setPerKeyCapacity(long perKeyCapacity) {
            this.perKeyCapacity = perKeyCapacity;
        }

        public Duration getPerKeyWindow() {
            return perKeyWindow;
        }

        public void setPerKeyWindow(Duration perKeyWindow) {
            this.perKeyWindow = perKeyWindow;
        }

        public long getPerIpCapacity() {
            return perIpCapacity;
        }

        public void setPerIpCapacity(long perIpCapacity) {
            this.perIpCapacity = perIpCapacity;
        }

        public Duration getPerIpWindow() {
            return perIpWindow;
        }

        public void setPerIpWindow(Duration perIpWindow) {
            this.perIpWindow = perIpWindow;
        }
    }
}
