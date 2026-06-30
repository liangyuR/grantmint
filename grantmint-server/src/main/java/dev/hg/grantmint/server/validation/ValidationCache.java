package dev.hg.grantmint.server.validation;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import java.time.Duration;
import java.util.function.Function;

/**
 * The Caffeine-backed validation-snapshot cache, keyed by license key id. Bounded by size and a
 * write TTL; the TTL doubles as the revocation-latency ceiling (see {@link ValidationProperties}).
 *
 * <p>A loader that throws (e.g. an unknown key id) propagates without poisoning the cache — Caffeine
 * stores nothing for a failed load, so the next request re-attempts rather than serving a cached
 * miss. The {@link #evict} hooks let the future license-mutation paths (M6 activation, M7 lifecycle)
 * drop a stale entry the instant a status or seat count changes.
 */
public class ValidationCache {

    private final Cache<String, ValidationSnapshot> cache;

    public ValidationCache(Duration ttl, long maximumSize) {
        this(ttl, maximumSize, Ticker.systemTicker());
    }

    /**
     * Test/advanced seam taking an explicit {@link Ticker} so the write-TTL — the revocation-latency
     * ceiling — can be exercised deterministically without real time passing.
     */
    ValidationCache(Duration ttl, long maximumSize, Ticker ticker) {
        this.cache = Caffeine.newBuilder()
                .maximumSize(maximumSize)
                .expireAfterWrite(ttl)
                .ticker(ticker)
                .build();
    }

    /** Return the cached snapshot, computing and storing it via {@code loader} on a miss. */
    public ValidationSnapshot get(String keyId, Function<String, ValidationSnapshot> loader) {
        return cache.get(keyId, loader);
    }

    /** The cached snapshot if present, without triggering a load. */
    public ValidationSnapshot getIfPresent(String keyId) {
        return cache.getIfPresent(keyId);
    }

    /** Drop a single license's snapshot — call on revoke/suspend/reinstate/activation change. */
    public void evict(String keyId) {
        cache.invalidate(keyId);
    }

    /** Drop everything (administrative flush / test reset). */
    public void evictAll() {
        cache.invalidateAll();
    }
}
