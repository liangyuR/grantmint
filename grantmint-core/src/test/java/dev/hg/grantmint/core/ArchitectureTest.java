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
                        // The minimal-codec rule: CanonicalJson/Base64Url are core's ONLY
                        // serialization mechanism — the canonical bytes are the security contract,
                        // and a general-purpose JSON library would be a second opinion about them.
                        // Ban every JSON binding a contributor might plausibly reach for, not just
                        // Jackson (M13 audit: the ban was Jackson-only, so gson/org.json could slip
                        // in unnoticed).
                        "com.fasterxml.jackson..",
                        "com.google.gson..",
                        "org.json..",
                        "jakarta.json..",
                        "javax.json..")
                .because("grantmint-core must remain a pure, framework-agnostic crypto/issuance "
                        + "library so it stays reusable, trivially testable, and AOT-friendly "
                        + "(CanonicalJson/Base64Url are its only codec — never a JSON library).");

        rule.check(CORE_CLASSES);
    }
}
