package dev.hg.grantmint.client;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.Test;

/**
 * The licensing boundary, build-enforced: the starter ships under Apache-2.0, so its main sources
 * must never depend on the AGPL {@code grantmint-core} — the verifier under {@code client.verify}
 * is deliberately fresh code, pinned to the reference byte-for-byte by the parity suite instead of
 * by sharing it. The core artifact is on this module's classpath ONLY at test scope (the parity
 * suite mints reference tokens with it), which is exactly why this rule can exist and exactly what
 * makes it necessary: a main-scope import would compile in an IDE and only fail at Maven scope
 * resolution, with a confusing error long after the line was written. This test names the rule
 * (M13 audit: the boundary was convention-only).
 */
class ArchitectureTest {

    private static final JavaClasses STARTER_MAIN_CLASSES = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.hg.grantmint.client");

    @Test
    void apacheLicensedStarterNeverDependsOnAgplCore() {
        noClasses()
                .should()
                .dependOnClassesThat()
                .resideInAnyPackage("dev.hg.grantmint.core..")
                .because("the Apache-2.0 starter must stay AGPL-free: grantmint-core is test-scope "
                        + "only (parity fixtures), and the shipped verifier is independent code "
                        + "held equivalent by the cross-verifier suite, not by code sharing")
                .check(STARTER_MAIN_CLASSES);
    }
}
