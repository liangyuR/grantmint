package dev.hg.grantmint.server.metrics;

import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.MachineActivationRepository;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.binder.MeterBinder;
import java.util.function.LongSupplier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Gauges that reflect database state, registered once at startup and re-sampled on every Prometheus
 * scrape (docs/operations/MONITORING_LOGGING.md, "How metrics are registered"). Each scrape costs
 * two indexed COUNT queries — cheap at the 15s scrape cadence, and always current without a
 * refresh job.
 */
@Configuration
public class MetricsConfig {

    @Bean
    MeterBinder grantmintDatabaseGauges(LicenseRepository licenses, MachineActivationRepository activations) {
        return registry -> {
            Gauge.builder(
                            "grantmint.licenses.active",
                            () -> sampleSafely(() -> licenses.countByStatus(LicenseStatus.ACTIVE)))
                    .tag("product", "all")
                    .description("Currently active licenses")
                    .register(registry);
            Gauge.builder("grantmint.seats.used", () -> sampleSafely(() -> activations.countActive()))
                    .tag("product", "all")
                    .description("Occupied seats (active machine activations) across all licenses")
                    .register(registry);
        };
    }

    /**
     * A gauge's value function runs on the scrape thread; a database hiccup must yield a NaN sample
     * (Prometheus drops it) rather than an exception that aborts the whole scrape.
     */
    private static double sampleSafely(LongSupplier query) {
        try {
            return query.getAsLong();
        } catch (RuntimeException databaseUnavailable) {
            return Double.NaN;
        }
    }
}
