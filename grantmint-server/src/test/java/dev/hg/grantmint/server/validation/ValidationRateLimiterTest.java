package dev.hg.grantmint.server.validation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ValidationRateLimiter} — the per-key and per-IP token buckets and, critically,
 * the guarantee that a request blocked by one dimension does not waste a token in the other (the
 * refund path). The per-IP dimension is exercised here deterministically rather than by hammering the
 * full HTTP stack hundreds of times.
 */
class ValidationRateLimiterTest {

    @Test
    void perKeyBucketRejectsPastCapacity() {
        ValidationRateLimiter limiter = new ValidationRateLimiter(limits(true, 3, 1000));

        // Distinct IPs so the IP dimension never bottlenecks; only the shared key bucket drains.
        for (int i = 0; i < 3; i++) {
            limiter.check("K7QF-9M2T-4XR8", "ip-" + i);
        }

        assertThatThrownBy(() -> limiter.check("K7QF-9M2T-4XR8", "ip-final"))
                .isInstanceOf(RateLimitExceededException.class);
    }

    @Test
    void perIpBucketRejectsPastCapacityAcrossDifferentKeys() {
        ValidationRateLimiter limiter = new ValidationRateLimiter(limits(true, 1000, 3));

        // Distinct keys so the key dimension never bottlenecks; only the shared IP bucket drains.
        for (int i = 0; i < 3; i++) {
            limiter.check("KEY-" + i, "203.0.113.7");
        }

        assertThatThrownBy(() -> limiter.check("KEY-final", "203.0.113.7"))
                .isInstanceOf(RateLimitExceededException.class);
    }

    @Test
    void aRequestBlockedByTheIpDimensionDoesNotSpendAKeyToken() {
        // perIp=1 (drained on the first request), perKey=5.
        ValidationRateLimiter limiter = new ValidationRateLimiter(limits(true, 5, 1));

        limiter.check("K1", "shared-ip"); // ok: IP -> 0, K1 -> 4

        // The IP bucket is now empty; charging K2 against it must reject AND refund K2's token.
        assertThatThrownBy(() -> limiter.check("K2", "shared-ip")).isInstanceOf(RateLimitExceededException.class);

        // Proof of no waste: K2 still holds its full 5 tokens — five fresh-IP requests all succeed,
        // and only the sixth (key-exhausted) is rejected.
        for (int i = 0; i < 5; i++) {
            limiter.check("K2", "fresh-ip-" + i);
        }
        assertThatThrownBy(() -> limiter.check("K2", "fresh-ip-final")).isInstanceOf(RateLimitExceededException.class);
    }

    @Test
    void rejectionCarriesAPositiveRetryAfter() {
        ValidationRateLimiter limiter = new ValidationRateLimiter(limits(true, 1, 1000));
        limiter.check("K", "ip-a");

        Throwable thrown = catchThrowable(() -> limiter.check("K", "ip-b"));

        assertThat(thrown).isInstanceOf(RateLimitExceededException.class);
        assertThat(((RateLimitExceededException) thrown).retryAfterSeconds()).isGreaterThanOrEqualTo(1L);
    }

    @Test
    void disabledLimiterNeverRejects() {
        ValidationRateLimiter limiter = new ValidationRateLimiter(limits(false, 1, 1));
        for (int i = 0; i < 100; i++) {
            limiter.check("K", "same-ip");
        }
    }

    @Test
    void nullDimensionsAreSkipped() {
        ValidationRateLimiter limiter = new ValidationRateLimiter(limits(true, 1, 1));
        // A null key skips the key bucket; a null ip skips the ip bucket. Neither should throw here.
        limiter.check(null, "ip-only");
        limiter.check("key-only", null);
    }

    private static ValidationProperties.RateLimit limits(boolean enabled, long perKey, long perIp) {
        ValidationProperties.RateLimit limit = new ValidationProperties.RateLimit();
        limit.setEnabled(enabled);
        limit.setPerKeyCapacity(perKey);
        limit.setPerKeyWindow(Duration.ofMinutes(1));
        limit.setPerIpCapacity(perIp);
        limit.setPerIpWindow(Duration.ofMinutes(1));
        return limit;
    }
}
