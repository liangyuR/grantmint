package dev.hg.grantmint.server;

import static com.tngtech.archunit.library.Architectures.layeredArchitecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.Test;

/**
 * Freezes the one-directional layering of {@code grantmint-server}: Web → Service → Domain.
 *
 * <p>Controllers (the Web layer) may call services; services may touch the domain (entities and
 * repositories); nothing flows back the other way. The service layer bridges JPA entities to
 * the framework-free {@code grantmint-core} types, so the domain never reaches up into the API.
 * As the milestones fill these packages in, this rule keeps the dependency arrows honest. See
 * docs/getting-started/DEVELOPMENT_GUIDE.md.
 */
class LayeringArchitectureTest {

    private static final JavaClasses SERVER_CLASSES = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.hg.grantmint.server");

    @Test
    void webDependsOnServiceDependsOnDomainOnly() {
        ArchRule rule = layeredArchitecture()
                .consideringOnlyDependenciesInLayers()
                // The layers are progressively filled in across milestones M1–M8; until then an
                // empty layer is expected, not a violation.
                .withOptionalLayers(true)
                .layer("Web")
                .definedBy("dev.hg.grantmint.server.api..")
                .layer("Service")
                .definedBy(
                        "dev.hg.grantmint.server.issuance..",
                        "dev.hg.grantmint.server.validation..",
                        "dev.hg.grantmint.server.activation..",
                        "dev.hg.grantmint.server.lifecycle..",
                        "dev.hg.grantmint.server.webhook..",
                        "dev.hg.grantmint.server.signing..",
                        "dev.hg.grantmint.server.audit..",
                        "dev.hg.grantmint.server.admin..",
                        // The auth subsystem (filters, key/session services, principals) is a service
                        // like any other: controllers may use its types, it may touch domain/repo, and
                        // it must never reach up into the api package. Omitting it here would exempt
                        // every dependency to/from it (consideringOnlyDependenciesInLayers) — the
                        // blind spot the M6–M10 audit flagged.
                        "dev.hg.grantmint.server.security..",
                        // Metrics instrumentation is a service-layer concern: the issuance/validation
                        // services record into it, and its DB-backed gauges read repositories.
                        "dev.hg.grantmint.server.metrics..")
                .layer("Domain")
                .definedBy("dev.hg.grantmint.server.domain..", "dev.hg.grantmint.server.repo..")
                .whereLayer("Web")
                .mayNotBeAccessedByAnyLayer()
                .whereLayer("Service")
                .mayOnlyBeAccessedByLayers("Web")
                .whereLayer("Domain")
                .mayOnlyBeAccessedByLayers("Web", "Service");

        rule.check(SERVER_CLASSES);
    }
}
