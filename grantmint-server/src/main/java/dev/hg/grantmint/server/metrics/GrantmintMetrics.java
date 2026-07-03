package dev.hg.grantmint.server.metrics;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

/**
 * The single place Grantmint-owned meter names and tag keys are spelled, so the service-layer call
 * sites cannot drift from the published catalog in docs/operations/MONITORING_LOGGING.md. All
 * metrics live under the {@code grantmint.} prefix and are tagged only with low-cardinality
 * dimensions (product slug, policy code, small enums) — never {@code keyId}, license id, or holder
 * data, which would explode Prometheus cardinality and leak per-customer facts.
 *
 * <p>{@code grantmint-core} is Spring- and Micrometer-free (ArchUnit-enforced); instrumentation
 * happens here in the server service layer that wraps it.
 */
@Component
public class GrantmintMetrics {

    private final MeterRegistry registry;

    public GrantmintMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    /** Start a latency sample; pass it to one of the {@code record*} methods to stop it. */
    public Timer.Sample start() {
        return Timer.start(registry);
    }

    /**
     * A successful mint: {@code grantmint.issuance.total} plus the {@code grantmint.issuance.latency}
     * timer (Ed25519 sign + persist). Failed issuance attempts (unknown policy, cross-product denial)
     * are not licenses issued and are deliberately not counted here.
     */
    public void recordIssuance(Timer.Sample sample, String productSlug, String policyCode, String source) {
        sample.stop(Timer.builder("grantmint.issuance.latency")
                .description("Time to mint a signed license token (Ed25519 sign + persist)")
                .tag("product", productSlug)
                .register(registry));
        registry.counter("grantmint.issuance.total", "product", productSlug, "policy", policyCode, "source", source)
                .increment();
    }

    /**
     * An online validation outcome: {@code grantmint.validation.total} tagged with the result enum,
     * plus the hot-path SLI timer {@code grantmint.validation.latency} tagged with whether the
     * snapshot came from the Caffeine cache.
     */
    public void recordValidation(Timer.Sample sample, String productSlug, boolean cacheHit, String result) {
        sample.stop(Timer.builder("grantmint.validation.latency")
                .description("Online validation latency — the hot-path SLI")
                .tag("product", productSlug)
                .tag("cache", cacheHit ? "hit" : "miss")
                .register(registry));
        registry.counter("grantmint.validation.total", "product", productSlug, "result", result)
                .increment();
    }
}
