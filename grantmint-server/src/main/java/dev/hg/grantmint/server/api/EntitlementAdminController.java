package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.admin.PolicyEntitlementService;
import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.domain.Entitlement;
import dev.hg.grantmint.server.security.AdminPrincipal;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Admin CRUD for policy entitlements. Every mutation triggers a rebuild of the policy's denormalized
 * {@code entitlements} jsonb snapshot via {@link PolicyEntitlementService}. Every mutation is
 * audited.
 */
@RestController
@RequestMapping("/admin/policies/{policyId}/entitlements")
@Tag(name = "Entitlements (admin)", description = "Admin CRUD for policy entitlements; rebuilds the jsonb snapshot.")
@SecurityRequirement(name = OpenApiConfig.ADMIN_SESSION)
public class EntitlementAdminController {

    private final PolicyEntitlementService policyService;
    private final AuditService audit;

    public EntitlementAdminController(PolicyEntitlementService policyService, AuditService audit) {
        this.policyService = policyService;
        this.audit = audit;
    }

    @PostMapping
    @Operation(summary = "Add an entitlement to a policy")
    ResponseEntity<EntitlementView> create(
            @PathVariable UUID policyId,
            @RequestBody CreateEntitlementRequest request,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        Entitlement entitlement =
                policyService.createEntitlement(policyId, request.code(), request.valueType(), request.value());
        audit.record(
                admin.username(),
                AuditActorType.ADMIN,
                "entitlement.created",
                "entitlement",
                entitlement.getId().toString(),
                Map.of("policy_id", policyId.toString(), "code", request.code()),
                httpRequest.getRemoteAddr());
        return ResponseEntity.status(HttpStatus.CREATED).body(EntitlementView.of(entitlement));
    }

    @GetMapping
    @Operation(summary = "List a policy's entitlements")
    List<EntitlementView> list(@PathVariable UUID policyId) {
        return policyService.listEntitlements(policyId).stream()
                .map(EntitlementView::of)
                .toList();
    }

    @PutMapping("/{entitlementId}")
    @Operation(summary = "Update an entitlement")
    EntitlementView update(
            @PathVariable UUID policyId,
            @PathVariable UUID entitlementId,
            @RequestBody UpdateEntitlementRequest request,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        Entitlement entitlement =
                policyService.updateEntitlement(policyId, entitlementId, request.valueType(), request.value());
        audit.record(
                admin.username(),
                AuditActorType.ADMIN,
                "entitlement.updated",
                "entitlement",
                entitlement.getId().toString(),
                Map.of("policy_id", policyId.toString()),
                httpRequest.getRemoteAddr());
        return EntitlementView.of(entitlement);
    }

    @DeleteMapping("/{entitlementId}")
    @Operation(summary = "Delete an entitlement")
    ResponseEntity<Void> delete(
            @PathVariable UUID policyId,
            @PathVariable UUID entitlementId,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        policyService.deleteEntitlement(policyId, entitlementId);
        audit.record(
                admin.username(),
                AuditActorType.ADMIN,
                "entitlement.deleted",
                "entitlement",
                entitlementId.toString(),
                Map.of("policy_id", policyId.toString()),
                httpRequest.getRemoteAddr());
        return ResponseEntity.noContent().build();
    }

    /**
     * @param code capability code matching {@code ^[a-z][a-z0-9_]{0,62}$}
     * @param valueType {@code flag | limit | string}
     * @param value boolean / integer / string matching the declared valueType
     */
    public record CreateEntitlementRequest(String code, String valueType, Object value) {}

    /**
     * @param valueType {@code flag | limit | string}
     * @param value boolean / integer / string matching the declared valueType
     */
    public record UpdateEntitlementRequest(String valueType, Object value) {}

    public record EntitlementView(
            UUID id,
            UUID policyId,
            String code,
            String valueType,
            Map<String, Object> value,
            OffsetDateTime createdAt) {

        /**
         * The policy id is accessed via the Hibernate lazy proxy's {@code @Id} getter, which does not
         * trigger loading.
         */
        static EntitlementView of(Entitlement e) {
            return new EntitlementView(
                    e.getId(), e.getPolicy().getId(), e.getCode(), e.getValueType(), e.getValue(), e.getCreatedAt());
        }
    }
}
