package dev.hg.grantmint.core.time;

import java.time.Instant;
import java.util.Objects;

/**
 * The single source of "now" for {@code grantmint-core}.
 *
 * <p>Token expiry ({@code exp}) and not-before ({@code nbf}) decisions are correctness-critical: a
 * verifier that reads the wall clock directly cannot be deterministically property-tested, and a
 * signer that does the same cannot be reproduced. Core code therefore <strong>never</strong> calls
 * {@link Instant#now()} directly — it asks an injected {@code Clock}. Production code passes
 * {@link #system()}; tests pass {@link #fixed(Instant)} to pin time exactly.
 *
 * <p>This is a deliberately tiny, framework-free abstraction (not {@link java.time.Clock}) so the
 * core stays reflection-free and trivial to fake.
 */
@FunctionalInterface
public interface Clock {

    /** The current instant, truncated to whatever precision the implementation provides. */
    Instant now();

    /** Current epoch seconds (UTC) — the unit token claims {@code iat}/{@code exp}/{@code nbf} use. */
    default long nowEpochSecond() {
        return now().getEpochSecond();
    }

    /** A clock backed by the system wall clock. The only place core observes real time. */
    static Clock system() {
        return Instant::now;
    }

    /** A clock frozen at {@code instant} — for tests and reproducible signing. */
    static Clock fixed(Instant instant) {
        Objects.requireNonNull(instant, "instant");
        return () -> instant;
    }
}
