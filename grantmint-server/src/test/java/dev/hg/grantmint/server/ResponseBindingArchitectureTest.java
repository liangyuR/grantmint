package dev.hg.grantmint.server;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.domain.JavaParameterizedType;
import com.tngtech.archunit.core.domain.JavaType;
import com.tngtech.archunit.core.domain.JavaWildcardType;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

/**
 * Freezes a native-image survival rule: every {@code ResponseEntity} a controller returns must
 * name a concrete body type.
 *
 * <p>Spring AOT derives the Jackson reflection hints for the native image from controller method
 * <em>signatures</em> ({@code BindingReflectionHintsRegistrar}). A {@code ResponseEntity<?>},
 * raw {@code ResponseEntity}, or {@code ResponseEntity<Object>} hides the real body type, so the
 * record it actually returns gets no hints — and the JVM build stays green while the native
 * binary answers 406 ("no acceptable representation") at runtime. That is exactly how admin
 * login shipped broken in the native image (GRANTMINT-119). Branchy handlers should throw and
 * let {@code ApiExceptionHandler} produce the error envelope instead of widening the signature.
 */
class ResponseBindingArchitectureTest {

    private static final JavaClasses SERVER_CLASSES = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.hg.grantmint.server");

    @Test
    void responseEntitiesDeclareConcreteBodyTypes() {
        ArchRule rule = ArchRuleDefinition.methods()
                .that()
                .haveRawReturnType(ResponseEntity.class)
                .should(declareAConcreteBodyType())
                .because("Spring AOT derives native-image Jackson hints from the method signature; "
                        + "a wildcard/raw/Object ResponseEntity ships a native binary that 406s at "
                        + "runtime while every JVM test passes (GRANTMINT-119)");

        rule.check(SERVER_CLASSES);
    }

    private static ArchCondition<JavaMethod> declareAConcreteBodyType() {
        return new ArchCondition<>("declare a concrete ResponseEntity body type") {
            @Override
            public void check(JavaMethod method, ConditionEvents events) {
                JavaType returnType = method.getReturnType();
                if (!(returnType instanceof JavaParameterizedType parameterized)) {
                    events.add(SimpleConditionEvent.violated(
                            method, method.getFullName() + " returns a raw ResponseEntity"));
                    return;
                }
                for (JavaType argument : parameterized.getActualTypeArguments()) {
                    if (argument instanceof JavaWildcardType) {
                        events.add(SimpleConditionEvent.violated(
                                method, method.getFullName() + " returns ResponseEntity<?>"));
                    } else if (argument.toErasure().isEquivalentTo(Object.class)) {
                        events.add(SimpleConditionEvent.violated(
                                method, method.getFullName() + " returns ResponseEntity<Object>"));
                    }
                }
            }
        };
    }
}
