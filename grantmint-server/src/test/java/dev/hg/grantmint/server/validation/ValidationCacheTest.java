package dev.hg.grantmint.server.validation;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.benmanes.caffeine.cache.Ticker;
import dev.hg.grantmint.server.domain.LicenseStatus;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * Behavioural tests for {@link ValidationCache} — the write-TTL is the documented revocation-latency
 * ceiling, so its expiry is exercised deterministically with a fake {@link Ticker} (no real sleeping)
 * to prove a cached snapshot ages out within exactly one TTL, and that an explicit evict closes the
 * window immediately.
 */
class ValidationCacheTest {

    private final AtomicLong nanos = new AtomicLong();
    private final Ticker ticker = nanos::get;

    @Test
    void servesCachedSnapshotUntilTtlElapsesThenReloads() {
        ValidationCache cache = new ValidationCache(Duration.ofSeconds(60), 100, ticker);
        AtomicLong loads = new AtomicLong();
        Function<String, ValidationSnapshot> loader = key -> {
            loads.incrementAndGet();
            return snapshot();
        };

        cache.get("K7QF-9M2T-4XR8", loader); // cold miss -> load #1
        advance(Duration.ofSeconds(59));
        cache.get("K7QF-9M2T-4XR8", loader); // still within TTL -> served from cache
        assertThat(loads.get()).isEqualTo(1);

        advance(Duration.ofSeconds(2)); // 61s total > 60s TTL
        cache.get("K7QF-9M2T-4XR8", loader); // expired -> reload #2
        assertThat(loads.get()).isEqualTo(2);
    }

    @Test
    void evictForcesAReloadBeforeTheTtlElapses() {
        ValidationCache cache = new ValidationCache(Duration.ofSeconds(60), 100, ticker);
        AtomicLong loads = new AtomicLong();
        Function<String, ValidationSnapshot> loader = key -> {
            loads.incrementAndGet();
            return snapshot();
        };

        cache.get("K7QF-9M2T-4XR8", loader);
        assertThat(cache.getIfPresent("K7QF-9M2T-4XR8")).isNotNull();

        cache.evict("K7QF-9M2T-4XR8");
        assertThat(cache.getIfPresent("K7QF-9M2T-4XR8")).isNull();

        cache.get("K7QF-9M2T-4XR8", loader); // evicted -> reload even though no time passed
        assertThat(loads.get()).isEqualTo(2);
    }

    private void advance(Duration duration) {
        nanos.addAndGet(duration.toNanos());
    }

    private static ValidationSnapshot snapshot() {
        return new ValidationSnapshot(
                UUID.randomUUID(), LicenseStatus.ACTIVE, true, null, null, 1, Map.of("team_sync", true));
    }
}
