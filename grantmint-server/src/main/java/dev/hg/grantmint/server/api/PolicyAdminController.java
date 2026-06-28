package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.admin.PolicyEntitlementService;
import dev.hg.grantmint.server.admin.PolicyEntitlementService.CreatePolicyCommand;
import dev.hg.grantmint.server.admin.PolicyEntitlementService.UpdatePolicyCommand;
import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.security.AdminPrincipal;
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
import org.springframework.web.bind.annotation.RestController;

/**
 * Admin CRUD for policies. Create and list are nested under a product; get/update/delete address
 * policies directly by ID. Code and product are immutable after creation. Every mutation is audited.
 */
@RestController
public class PolicyAdminController {

    private final PolicyEntitlementService policyService;
    private final AuditService audit;

    public PolicyAdminController(PolicyEntitlementService policyService, AuditService audit) {
        this.policyService = policyService;
        this.audit = audit;
    }

    @PostMapping("/admin/products/{productId}/policies")
    ResponseEntity<PolicyView> create(
            @PathVariable UUID productId,
            @RequestBody CreatePolicyRequest request,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        Policy policy = policyService.createPolicy(
                productId,
                new CreatePolicyCommand(
                        request.code(),
                        request.name(),
                        request.activationType(),
                        request.maxSeats(),
                        request.durationDays(),
                        request.gracePeriodDays(),
                        request.trial(),
                        request.heartbeatIntervalSeconds(),
                        request.constraints()));
        audit.record(
                admin.username(),
                AuditActorType.ADMIN,
                "policy.created",
                "policy",
                policy.getId().toString(),
                Map.of("product_id", productId.toString()),
                httpRequest.getRemoteAddr());
        return ResponseEntity.status(HttpStatus.CREATED).body(PolicyView.of(policy));
    }

    @GetMapping("/admin/products/{productId}/policies")
    List<PolicyView> list(@PathVariable UUID productId) {
        return policyService.listPolicies(productId).stream()
                .map(PolicyView::of)
                .toList();
    }

    @GetMapping("/admin/policies/{policyId}")
    PolicyView get(@PathVariable UUID policyId) {
        return PolicyView.of(policyService.getPolicy(policyId));
    }

    @PutMapping("/admin/policies/{policyId}")
    PolicyView update(
            @PathVariable UUID policyId,
            @RequestBody UpdatePolicyRequest request,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        Policy policy = policyService.updatePolicy(
                policyId,
                new UpdatePolicyCommand(
                        request.name(),
                        request.activationType(),
                        request.maxSeats(),
                        request.durationDays(),
                        request.gracePeriodDays(),
                        request.trial(),
                        request.heartbeatIntervalSeconds(),
                        request.constraints()));
        audit.record(
                admin.username(),
                AuditActorType.ADMIN,
                "policy.updated",
                "policy",
                policy.getId().toString(),
                Map.of(),
                httpRequest.getRemoteAddr());
        return PolicyView.of(policy);
    }

    @DeleteMapping("/admin/policies/{policyId}")
    ResponseEntity<Void> delete(
            @PathVariable UUID policyId,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        policyService.deletePolicy(policyId);
        audit.record(
                admin.username(),
                AuditActorType.ADMIN,
                "policy.deleted",
                "policy",
                policyId.toString(),
                Map.of(),
                httpRequest.getRemoteAddr());
        return ResponseEntity.noContent().build();
    }

    public record CreatePolicyRequest(
            String code,
            String name,
            String activationType,
            Integer maxSeats,
            Integer durationDays,
            Integer gracePeriodDays,
            Boolean trial,
            Integer heartbeatIntervalSeconds,
            Map<String, Object> constraints) {}

    public record UpdatePolicyRequest(
            String name,
            String activationType,
            Integer maxSeats,
            Integer durationDays,
            Integer gracePeriodDays,
            Boolean trial,
            Integer heartbeatIntervalSeconds,
            Map<String, Object> constraints) {}

    public record PolicyView(
            UUID id,
            UUID productId,
            String code,
            String name,
            String activationType,
            int maxSeats,
            Integer durationDays,
            int gracePeriodDays,
            boolean trial,
            int heartbeatIntervalSeconds,
            Map<String, Object> entitlements,
            Map<String, Object> constraints,
            OffsetDateTime createdAt,
            OffsetDateTime updatedAt) {

        /**
         * Hibernate exposes the product id via the lazy proxy without triggering a load; the
         * {@code @Id} getter is intercepted by the enhanced proxy and returns the FK value directly.
         */
        static PolicyView of(Policy p) {
            return new PolicyView(
                    p.getId(),
                    p.getProduct().getId(),
                    p.getCode(),
                    p.getName(),
                    p.getActivationType(),
                    p.getMaxSeats(),
                    p.getDurationDays(),
                    p.getGracePeriodDays(),
                    p.isTrial(),
                    p.getHeartbeatIntervalSeconds(),
                    p.getEntitlements(),
                    p.getConstraints(),
                    p.getCreatedAt(),
                    p.getUpdatedAt());
        }
    }
}
