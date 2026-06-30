package dev.hg.grantmint.server.validation;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;

/**
 * Token-bucket rate limiter for the validation hot path, enforced per license key id <em>and</em>
 * per source IP — a single abusive key cannot exhaust the service, and a single IP cannot hammer
 * across many keys. Each dimension has its own bucket store, bounded in size and expiring idle
 * buckets so the limiter's own memory stays bounded.
 *
 * <p>A request must spend a token from <em>both</em> applicable buckets. The dimensions are charged
 * in order (key, then IP); if a later dimension rejects, the token already taken from the earlier one
 * is <em>refunded</em>, so a blocked request never permanently spends a token in the dimension that
 * was not the bottleneck. The {@link RateLimitExceededException}'s {@code Retry-After} reflects the
 * wait of the dimension that actually rejected. Limits are configurable per deployment (see {@link
 * ValidationProperties.RateLimit}); setting {@code grantmint.validation.rate-limit.enabled=false}
 * disables enforcement entirely.
 */
public class ValidationRateLimiter {

    private final boolean enabled;
    private final long perKeyCapacity;
    private final Duration perKeyWindow;
    private final long perIpCapacity;
    private final Duration perIpWindow;
    private final Cache<String, TokenBucket> keyBuckets;
    private final Cache<String, TokenBucket> ipBuckets;

    public ValidationRateLimiter(ValidationProperties.RateLimit props) {
        this.enabled = props.isEnabled();
        this.perKeyCapacity = props.getPerKeyCapacity();
        this.perKeyWindow = props.getPerKeyWindow();
        this.perIpCapacity = props.getPerIpCapacity();
        this.perIpWindow = props.getPerIpWindow();
        this.keyBuckets = bucketStore(perKeyWindow);
        this.ipBuckets = bucketStore(perIpWindow);
    }

    /**
     * Charge one request against the key and IP buckets.
     *
     * @throws RateLimitExceededException if either dimension is over its limit (rendered as 429)
     */
    public void check(String keyId, String ip) {
        if (!enabled) {
            return;
        }
        TokenBucket keyBucket =
                keyId == null ? null : keyBuckets.get(keyId, k -> new TokenBucket(perKeyCapacity, perKeyWindow));
        TokenBucket ipBucket = ip == null ? null : ipBuckets.get(ip, k -> new TokenBucket(perIpCapacity, perIpWindow));

        // Charge the key dimension first. If it rejects, the IP bucket is never touched.
        if (keyBucket != null && !keyBucket.tryConsume()) {
            throw new RateLimitExceededException(Math.max(1L, keyBucket.retryAfterSeconds()));
        }
        // Then the IP dimension. If it rejects, refund the key token so the request — which was not
        // admitted — leaves no dent in the key bucket.
        if (ipBucket != null && !ipBucket.tryConsume()) {
            if (keyBucket != null) {
                keyBucket.refund();
            }
            throw new RateLimitExceededException(Math.max(1L, ipBucket.retryAfterSeconds()));
        }
    }

    /** Drop all buckets (administrative reset / test isolation). */
    public void reset() {
        keyBuckets.invalidateAll();
        ipBuckets.invalidateAll();
    }

    private static Cache<String, TokenBucket> bucketStore(Duration window) {
        // Idle buckets are full anyway, so dropping them after a couple of windows is free and bounds memory.
        return Caffeine.newBuilder()
                .maximumSize(100_000)
                .expireAfterAccess(window.multipliedBy(2))
                .build();
    }
}
