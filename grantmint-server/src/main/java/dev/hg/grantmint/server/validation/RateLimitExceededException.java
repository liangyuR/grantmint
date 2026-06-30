package dev.hg.grantmint.server.validation;

/**
 * Thrown when a caller exceeds the validation-path rate limit (per license key or per source IP).
 * The API renders it as {@code 429 Too Many Requests} with a {@code Retry-After} header. See
 * docs/api/API_DOCUMENTATION.md (rate limits).
 */
public class RateLimitExceededException extends RuntimeException {

    private final long retryAfterSeconds;

    public RateLimitExceededException(long retryAfterSeconds) {
        super("Rate limit exceeded; retry after " + retryAfterSeconds + "s");
        this.retryAfterSeconds = retryAfterSeconds;
    }

    /** Seconds the client should wait before retrying — the {@code Retry-After} value. */
    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
