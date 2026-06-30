package dev.hg.grantmint.server.validation;

import java.time.Duration;
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

    public Cache getCache() {
        return cache;
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
}
