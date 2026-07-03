package dev.hg.grantmint.server.validation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.metrics.GrantmintMetrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The validation path's instrumentation contract: every outcome lands in
 * {@code grantmint.validation.total} with the catalog's {@code result} vocabulary, and the
 * {@code grantmint.validation.latency} SLI timer tags whether the snapshot came from the Caffeine
 * cache — with only low-cardinality tags (product slug, result enum), never the key id. See
 * docs/operations/MONITORING_LOGGING.md.
 */
class ValidationMetricsTest {

    private static final UUID PRODUCT_ID = UUID.randomUUID();
    private static final String KEY_ID = "K7QF-9M2T-4XR8";

    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();

    @Test
    void validOutcomeCountsValidAndTagsCacheMissThenHit() {
        ValidationService service = service(snapshot(LicenseStatus.ACTIVE));

        service.validate(KEY_ID, PRODUCT_ID, null);
        service.validate(KEY_ID, PRODUCT_ID, null);

        assertThat(registry.get("grantmint.validation.total")
                        .tags("product", "acme-notes", "result", "valid")
                        .counter()
                        .count())
                .isEqualTo(2.0);
        assertThat(registry.get("grantmint.validation.latency")
                        .tags("product", "acme-notes", "cache", "miss")
                        .timer()
                        .count())
                .isEqualTo(1);
        assertThat(registry.get("grantmint.validation.latency")
                        .tags("product", "acme-notes", "cache", "hit")
                        .timer()
                        .count())
                .isEqualTo(1);
    }

    @Test
    void unhealthyLicenseCountsItsCatalogResult() {
        ValidationService service = service(snapshot(LicenseStatus.REVOKED));

        assertThatThrownBy(() -> service.validate(KEY_ID, PRODUCT_ID, null))
                .isInstanceOf(LicenseNotValidException.class);

        assertThat(registry.get("grantmint.validation.total")
                        .tags("product", "acme-notes", "result", "revoked")
                        .counter()
                        .count())
                .isEqualTo(1.0);
    }

    @Test
    void unknownKeyIdCountsNotFoundWithoutAProductToLeak() {
        ValidationService service = service(null); // loader throws NoSuchElementException

        assertThatThrownBy(() -> service.validate(KEY_ID, PRODUCT_ID, null)).isInstanceOf(NoSuchElementException.class);

        assertThat(registry.get("grantmint.validation.total")
                        .tags("product", "unknown", "result", "not_found")
                        .counter()
                        .count())
                .isEqualTo(1.0);
    }

    @Test
    void crossProductRejectionCountsNotFound() {
        ValidationService service = service(snapshot(LicenseStatus.ACTIVE));

        assertThatThrownBy(() -> service.validate(KEY_ID, UUID.randomUUID(), null))
                .isInstanceOf(NoSuchElementException.class);

        assertThat(registry.get("grantmint.validation.total")
                        .tags("product", "acme-notes", "result", "not_found")
                        .counter()
                        .count())
                .isEqualTo(1.0);
    }

    /** A service over a fresh cache and a canned loader; a null snapshot means "unknown key id". */
    private ValidationService service(ValidationSnapshot snapshot) {
        ValidationSnapshotLoader loader = new ValidationSnapshotLoader(null, null, Clock.systemUTC()) {
            @Override
            public ValidationSnapshot load(String keyId) {
                if (snapshot == null) {
                    throw new NoSuchElementException("License not found: " + keyId);
                }
                return snapshot;
            }
        };
        return new ValidationService(
                new ValidationCache(Duration.ofMinutes(5), 100),
                loader,
                Clock.systemUTC(),
                new GrantmintMetrics(registry));
    }

    private static ValidationSnapshot snapshot(LicenseStatus status) {
        return new ValidationSnapshot(PRODUCT_ID, "acme-notes", status, true, null, null, 2, Map.of("team_sync", true));
    }
}
