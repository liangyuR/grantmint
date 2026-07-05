package dev.hg.grantmint.cli;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.Test;

/**
 * The offline surface of the CLI, build-enforced: {@code verify} and {@code keygen} (plus their
 * {@code TokenInput} helper) are documented to work with no server and no network — that is the
 * point of an offline-verifiable license. This rule keeps a future refactor from quietly wiring
 * {@code CliHttp} or {@code java.net} into them (M13 audit: the guarantee was only asserted in
 * docs, never by a test).
 */
class ArchitectureTest {

    private static final JavaClasses CLI_CLASSES = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.hg.grantmint.cli");

    @Test
    void offlineCommandsNeverTouchHttpOrTheNetwork() {
        noClasses()
                .that()
                .haveSimpleName("VerifyCommand")
                .or()
                .haveSimpleName("KeygenCommand")
                .or()
                .haveSimpleName("TokenInput")
                .should()
                .dependOnClassesThat()
                .haveSimpleName("CliHttp")
                .orShould()
                .dependOnClassesThat()
                .resideInAnyPackage("java.net..", "javax.net..")
                .because("`grantmint verify` and `grantmint keygen` are the offline promise: "
                        + "a token verifies and a key mints with no server reachable at all")
                .check(CLI_CLASSES);
    }
}
