package dev.hg.grantmint.server;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Guard against the security model's one structural blind spot (M13 audit): {@code
 * GrantmintSecurityConfig} is an allowlist of secured path prefixes, with no deny-all fallback
 * chain — deliberately, because a catch-all would also swallow the actuator endpoints on the
 * management port. That design means a controller route mapped OUTSIDE the known prefixes would be
 * silently unprotected by every filter chain. This rule makes that impossible to do by accident:
 * every <em>effective</em> route of every {@code @RestController} (class-level prefix + method
 * mapping, or an absolute method mapping when there is no class-level one) must sit under a prefix
 * one of the security chains covers (or {@code /webhooks}, whose auth is the provider signature,
 * verified before parsing — see WebhookController).
 */
class SecuredPrefixArchitectureTest {

    /** Must mirror the securityMatcher prefixes in GrantmintSecurityConfig + the webhook surface. */
    private static final List<String> COVERED_PREFIXES = List.of("/admin", "/issuance", "/v1/licenses", "/webhooks");

    private static final JavaClasses SERVER_CLASSES = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.hg.grantmint.server");

    @Test
    void everyControllerRouteSitsUnderASecurityCoveredPrefix() {
        classes()
                .that()
                .areAnnotatedWith(RestController.class)
                .should(mapOnlyUnderCoveredPrefixes())
                .because("the security config is an allowlist of path prefixes with no deny-all "
                        + "fallback (the actuator management port rules one out), so a route "
                        + "outside the known prefixes would be reachable with no auth at all")
                .check(SERVER_CLASSES);
    }

    private static ArchCondition<JavaClass> mapOnlyUnderCoveredPrefixes() {
        return new ArchCondition<>("map every route under one of " + COVERED_PREFIXES) {
            @Override
            public void check(JavaClass controller, ConditionEvents events) {
                List<String> classPaths = classLevelPaths(controller);
                List<String> effectivePaths = new ArrayList<>();
                for (JavaMethod method : controller.getMethods()) {
                    for (String methodPath : methodLevelPaths(method)) {
                        if (classPaths.isEmpty()) {
                            effectivePaths.add(methodPath);
                        } else {
                            for (String classPath : classPaths) {
                                effectivePaths.add(joinPaths(classPath, methodPath));
                            }
                        }
                    }
                }
                // A class-level prefix with no method mappings still anchors handler methods that
                // add no path of their own (e.g. a lone @PostMapping without a value).
                if (effectivePaths.isEmpty()) {
                    effectivePaths.addAll(classPaths);
                }
                if (effectivePaths.isEmpty()) {
                    events.add(SimpleConditionEvent.violated(
                            controller,
                            controller.getName() + " declares no request mappings at all — a "
                                    + "@RestController must anchor its routes under a secured prefix"));
                    return;
                }
                for (String path : effectivePaths) {
                    boolean covered = COVERED_PREFIXES.stream()
                            .anyMatch(prefix -> path.equals(prefix) || path.startsWith(prefix + "/"));
                    if (!covered) {
                        events.add(SimpleConditionEvent.violated(
                                controller,
                                controller.getName() + " maps '" + path + "', which no security "
                                        + "filter chain covers (known prefixes: " + COVERED_PREFIXES + ")"));
                        return;
                    }
                }
                events.add(SimpleConditionEvent.satisfied(
                        controller, controller.getName() + " maps only covered routes " + effectivePaths));
            }
        };
    }

    private static List<String> classLevelPaths(JavaClass controller) {
        if (!controller.isAnnotatedWith(RequestMapping.class)) {
            return List.of();
        }
        RequestMapping mapping = controller.getAnnotationOfType(RequestMapping.class);
        return List.of(mapping.value().length > 0 ? mapping.value() : mapping.path());
    }

    private static List<String> methodLevelPaths(JavaMethod method) {
        List<String> paths = new ArrayList<>();
        if (method.isAnnotatedWith(RequestMapping.class)) {
            RequestMapping m = method.getAnnotationOfType(RequestMapping.class);
            paths.addAll(List.of(m.value().length > 0 ? m.value() : m.path()));
        }
        if (method.isAnnotatedWith(GetMapping.class)) {
            GetMapping m = method.getAnnotationOfType(GetMapping.class);
            paths.addAll(List.of(m.value().length > 0 ? m.value() : m.path()));
        }
        if (method.isAnnotatedWith(PostMapping.class)) {
            PostMapping m = method.getAnnotationOfType(PostMapping.class);
            paths.addAll(List.of(m.value().length > 0 ? m.value() : m.path()));
        }
        if (method.isAnnotatedWith(PutMapping.class)) {
            PutMapping m = method.getAnnotationOfType(PutMapping.class);
            paths.addAll(List.of(m.value().length > 0 ? m.value() : m.path()));
        }
        if (method.isAnnotatedWith(DeleteMapping.class)) {
            DeleteMapping m = method.getAnnotationOfType(DeleteMapping.class);
            paths.addAll(List.of(m.value().length > 0 ? m.value() : m.path()));
        }
        if (method.isAnnotatedWith(PatchMapping.class)) {
            PatchMapping m = method.getAnnotationOfType(PatchMapping.class);
            paths.addAll(List.of(m.value().length > 0 ? m.value() : m.path()));
        }
        return paths;
    }

    private static String joinPaths(String classPath, String methodPath) {
        if (methodPath.isEmpty()) {
            return classPath;
        }
        String left = classPath.endsWith("/") ? classPath.substring(0, classPath.length() - 1) : classPath;
        return methodPath.startsWith("/") ? left + methodPath : left + "/" + methodPath;
    }
}
