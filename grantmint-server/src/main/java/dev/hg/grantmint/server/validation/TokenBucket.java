package dev.hg.grantmint.server.validation;

import java.time.Duration;

/**
 * A classic continuous-refill token bucket: {@code capacity} tokens that refill at a steady
 * {@code capacity / window} rate, allowing short bursts up to capacity while bounding the sustained
 * rate. One token is spent per request. Thread-safe — a single bucket is shared by all concurrent
 * requests for the same license key (or IP).
 *
 * <p>Time is read from {@link System#nanoTime()} (monotonic), so the bucket is immune to wall-clock
 * jumps. It is intentionally framework-free and self-contained.
 */
final class TokenBucket {

    private final double capacity;
    private final double refillTokensPerNano;

    private double tokens;
    private long lastRefillNanos;

    TokenBucket(long capacity, Duration window) {
        this.capacity = capacity;
        this.refillTokensPerNano = (double) capacity / window.toNanos();
        this.tokens = capacity;
        this.lastRefillNanos = System.nanoTime();
    }

    /** Spend one token if available; returns false when the bucket is empty (rate exceeded). */
    synchronized boolean tryConsume() {
        refill();
        if (tokens >= 1.0) {
            tokens -= 1.0;
            return true;
        }
        return false;
    }

    /**
     * Hand back a token taken by a {@link #tryConsume()} that ultimately did not admit the request —
     * used when a multi-dimension limiter consumes this bucket but another dimension rejects, so a
     * blocked request never permanently spends a token here. Capped at capacity; never over-fills.
     */
    synchronized void refund() {
        tokens = Math.min(capacity, tokens + 1.0);
    }

    /** Whole seconds until the next token is available; at least 1 while the bucket is empty. */
    synchronized long retryAfterSeconds() {
        refill();
        if (tokens >= 1.0) {
            return 0;
        }
        double tokensPerSecond = refillTokensPerNano * 1_000_000_000.0;
        double seconds = (1.0 - tokens) / tokensPerSecond;
        return Math.max(1L, (long) Math.ceil(seconds));
    }

    private void refill() {
        long now = System.nanoTime();
        double added = (now - lastRefillNanos) * refillTokensPerNano;
        if (added > 0) {
            tokens = Math.min(capacity, tokens + added);
            lastRefillNanos = now;
        }
    }
}
