package dev.hg.grantmint.server;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noFields;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToMany;
import org.junit.jupiter.api.Test;

/**
 * Build-enforces the domain model's equality precondition (2026-07 audit, GRANTMINT-171): the
 * entities rely on identity-based {@code equals}/{@code hashCode} (see the package-info of
 * {@code server.domain}), which is safe ONLY while no entity is held in a Hibernate-managed
 * collection. This rule turns that from a convention into a failing build — anyone mapping the
 * first {@code @OneToMany}/{@code @ManyToMany}/{@code @ElementCollection} is forced to decide the
 * equality strategy at the same time, instead of discovering set-membership bugs in production.
 */
class DomainModelArchitectureTest {

    private static final String REASON =
            "identity-based equals/hashCode (server.domain package-info) is safe only while no entity"
                    + " sits in a Hibernate-managed collection — introduce persisted-key equality in the"
                    + " same change as the first mapped collection (GRANTMINT-171)";

    private static final JavaClasses DOMAIN = new ClassFileImporter().importPackages("dev.hg.grantmint.server.domain");

    @Test
    void entitiesNeverMapHibernateManagedCollections() {
        noFields()
                .should()
                .beAnnotatedWith(OneToMany.class)
                .orShould()
                .beAnnotatedWith(ManyToMany.class)
                .orShould()
                .beAnnotatedWith(ElementCollection.class)
                .because(REASON)
                .check(DOMAIN);
        // Property-access mappings put the annotation on the getter — same ban.
        noMethods()
                .should()
                .beAnnotatedWith(OneToMany.class)
                .orShould()
                .beAnnotatedWith(ManyToMany.class)
                .orShould()
                .beAnnotatedWith(ElementCollection.class)
                .because(REASON)
                .check(DOMAIN);
    }
}
