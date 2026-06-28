package dev.hg.grantmint.core;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.Test;

/**
 * The load-bearing architectural guard for {@code grantmint-core}.
 *
 * <p>grantmint-core must remain a pure, framework-agnostic crypto/issuance library so it stays
 * reusable, trivially property-testable, and AOT-friendly. This test fails the build the moment
 * any class in the module reaches for Spring, JPA, the servlet API, or a JSON-binding library
 * (the core uses its own minimal Base64URL codec, never Jackson). See
 * docs/getting-started/DEVELOPMENT_GUIDE.md and docs/architecture/ARCHITECTURE.md.
 */
class ArchitectureTest {

    private static final JavaClasses CORE_CLASSES = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.hg.grantmint.core");

    @Test
    void coreHasNoFrameworkDependencies() {
        ArchRule rule = noClasses()
                .should()
                .dependOnClassesThat()
                .resideInAnyPackage(
                        "org.springframework..",
                        "jakarta.persistence..",
                        "jakarta.servlet..",
                        // Guard the legacy Java EE namespaces too, in case a stray transitive type slips in.
                        "javax.persistence..",
                        "javax.servlet..",
                        "com.fasterxml.jackson..")
                .because("grantmint-core must remain a pure, framework-agnostic crypto/issuance "
                        + "library so it stays reusable, trivially testable, and AOT-friendly "
                        + "(it uses its own minimal codec, never Jackson).");

        rule.check(CORE_CLASSES);
    }
}
