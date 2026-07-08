package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.activation.ActivationService;
import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.domain.MachineActivation;
import dev.hg.grantmint.server.issuance.IssuanceCommand;
import dev.hg.grantmint.server.issuance.IssuanceService;
import dev.hg.grantmint.server.issuance.IssuedLicense;
import dev.hg.grantmint.server.lifecycle.LicenseLifecycleService;
import dev.hg.grantmint.server.lifecycle.LicenseLifecycleService.LifecycleResult;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.MachineActivationRepository;
import dev.hg.grantmint.server.security.AdminPrincipal;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The admin license surface reachable from the dashboard's admin session — list, detail, issue, and
 * the suspend/reinstate/revoke/force-deactivate lifecycle actions. This mirrors the per-product
 * {@code /issuance/**} endpoints (Scheme 2, {@code SCOPE_ISSUE}/{@code SCOPE_REVOKE}) but for the
 * browser: an admin session sees every product, so {@code productId} is trusted straight from the
 * request body/path rather than bound to an authenticated key. See
 * docs/api/API_DOCUMENTATION.md ("Licenses (Issue & Lifecycle)", "Activations (Admin View)") — the
 * field shapes here are camelCase, matching the rest of the implemented API rather than the doc's
 * illustrative snake_case.
 */
@RestController
@RequestMapping("/admin/licenses")
@Tag(name = "Licenses (admin)", description = "Admin list/detail/issue/lifecycle for licenses.")
@SecurityRequirement(name = OpenApiConfig.ADMIN_SESSION)
public class LicenseAdminController {

    private static final int MAX_PAGE_SIZE = 100;

    private final LicenseRepository licenses;
    private final MachineActivationRepository activations;
    private final IssuanceService issuance;
    private final LicenseLifecycleService lifecycle;
    private final ActivationService activationService;

    public LicenseAdminController(
            LicenseRepository licenses,
            MachineActivationRepository activations,
            IssuanceService issuance,
            LicenseLifecycleService lifecycle,
            ActivationService activationService) {
        this.licenses = licenses;
        this.activations = activations;
        this.issuance = issuance;
        this.lifecycle = lifecycle;
        this.activationService = activationService;
    }

    @GetMapping
    @Operation(
            summary = "List licenses",
            description = "Paginated, filterable by status/holderEmail/productId/policyId/keyId (all optional "
                    + "ANDs). Never includes the signed token — see the detail endpoint for that.")
    LicenseListResponse list(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String holderEmail,
            @RequestParam(required = false) UUID productId,
            @RequestParam(required = false) UUID policyId,
            @RequestParam(required = false) String keyId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        int resolvedPage = Math.max(page, 0);
        int resolvedSize = Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
        Specification<License> spec = buildSpec(status, holderEmail, productId, policyId, keyId);
        Pageable pageable = PageRequest.of(resolvedPage, resolvedSize, Sort.by(Sort.Direction.DESC, "issuedAt"));
        Page<License> results = licenses.findAll(spec, pageable);
        // One grouped count for the whole page instead of a count query per row (post-M13 audit's
        // bounded N+1); licenses absent from the result have zero active seats.
        List<License> content = results.getContent();
        Map<UUID, Long> seatCounts = content.isEmpty()
                ? Map.of()
                : activations
                        .countActiveByLicenseIds(
                                content.stream().map(License::getId).toList())
                        .stream()
                        .collect(Collectors.toMap(row -> (UUID) row[0], row -> (Long) row[1]));
        List<LicenseSummaryView> items = content.stream()
                .map(l -> LicenseSummaryView.of(l, seatCounts.getOrDefault(l.getId(), 0L)))
                .toList();
        return new LicenseListResponse(items, resolvedPage, resolvedSize, results.getTotalElements());
    }

    private static Specification<License> buildSpec(
            String status, String holderEmail, UUID productId, UUID policyId, String keyId) {
        Specification<License> spec = Specification.where(null);
        if (status != null && !status.isBlank()) {
            LicenseStatus parsed = LicenseStatus.fromWire(status);
            spec = spec.and((root, query, cb) -> cb.equal(root.get("status"), parsed));
        }
        if (holderEmail != null && !holderEmail.isBlank()) {
            String normalized = holderEmail.toLowerCase(Locale.ROOT);
            spec = spec.and((root, query, cb) -> cb.equal(cb.lower(root.get("holderEmail")), normalized));
        }
        if (productId != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("product").get("id"), productId));
        }
        if (policyId != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("policy").get("id"), policyId));
        }
        if (keyId != null && !keyId.isBlank()) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("keyId"), keyId));
        }
        return spec;
    }

    @GetMapping("/{keyId}")
    @Operation(
            summary = "Get a license",
            description = "Includes the signed token (admins may re-fetch it), lifecycle stamps, and the "
                    + "activation list.")
    LicenseDetailView get(@PathVariable String keyId) {
        License license = licenses.findByKeyId(keyId)
                .orElseThrow(() -> new NoSuchElementException("License not found: " + keyId));
        List<MachineActivation> licenseActivations = activations.findByLicense_Id(license.getId());
        return LicenseDetailView.of(license, licenseActivations);
    }

    @PostMapping
    @Operation(
            summary = "Issue a license",
            description = "Admin mint: productId is trusted from the body — unlike the issuance-key path "
                    + "(/issuance/licenses), an admin session is not scoped to one product.")
    ResponseEntity<IssuedLicenseResponse> issue(
            @RequestBody IssueLicenseRequest request,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        if (request.productId() == null) {
            throw new IllegalArgumentException("productId is required");
        }
        if (request.policyId() == null) {
            throw new IllegalArgumentException("policyId is required");
        }
        if (request.holder() == null) {
            throw new IllegalArgumentException("holder is required");
        }
        IssuanceCommand command = new IssuanceCommand(
                request.productId(),
                request.policyId(),
                request.holder().name(),
                request.holder().email(),
                request.expiresAt(),
                request.seat(),
                request.externalRef(),
                admin.username(),
                httpRequest.getRemoteAddr());
        IssuedLicense issued = issuance.issue(command, AuditActorType.ADMIN);
        return ResponseEntity.status(HttpStatus.CREATED).body(IssuedLicenseResponse.of(issued));
    }

    @PostMapping("/{keyId}/suspend")
    @Operation(
            summary = "Suspend a license",
            description = "ACTIVE → SUSPENDED. Admin sees every product, so the cross-product guard is disabled "
                    + "(requesterProductId = null).")
    ResponseEntity<LifecycleResponse> suspend(
            @PathVariable String keyId,
            @RequestBody(required = false) ReasonRequest request,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        LifecycleResult result = lifecycle.suspend(
                keyId,
                null,
                request == null ? null : request.reason(),
                admin.username(),
                AuditActorType.ADMIN,
                httpRequest.getRemoteAddr());
        return ResponseEntity.ok(LifecycleResponse.of(result));
    }

    @PostMapping("/{keyId}/reinstate")
    @Operation(summary = "Reinstate a suspended license", description = "SUSPENDED → ACTIVE.")
    ResponseEntity<LifecycleResponse> reinstate(
            @PathVariable String keyId, @AuthenticationPrincipal AdminPrincipal admin, HttpServletRequest httpRequest) {
        LifecycleResult result =
                lifecycle.reinstate(keyId, null, admin.username(), AuditActorType.ADMIN, httpRequest.getRemoteAddr());
        return ResponseEntity.ok(LifecycleResponse.of(result));
    }

    @DeleteMapping("/{keyId}")
    @Operation(summary = "Revoke a license (terminal)", description = "Any non-revoked state → REVOKED.")
    ResponseEntity<LifecycleResponse> revoke(
            @PathVariable String keyId,
            @RequestBody(required = false) ReasonRequest request,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        LifecycleResult result = lifecycle.revoke(
                keyId,
                null,
                request == null ? null : request.reason(),
                admin.username(),
                AuditActorType.ADMIN,
                httpRequest.getRemoteAddr());
        return ResponseEntity.ok(LifecycleResponse.of(result));
    }

    @DeleteMapping("/{keyId}/activations/{activationId}")
    @Operation(
            summary = "Force-deactivate a seat",
            description = "Admin frees a seat regardless of which device holds it (e.g. a lost laptop). The "
                    + "freed seat is immediately available for a new activation.")
    ResponseEntity<Void> forceDeactivate(
            @PathVariable String keyId,
            @PathVariable UUID activationId,
            @AuthenticationPrincipal AdminPrincipal admin) {
        activationService.forceDeactivate(activationId, keyId, admin.username());
        return ResponseEntity.noContent().build();
    }

    /** @param holder required customer identity; @param expiresAt/seat null → use the policy's own values */
    public record IssueLicenseRequest(
            UUID productId,
            UUID policyId,
            HolderRequest holder,
            OffsetDateTime expiresAt,
            Integer seat,
            String externalRef) {}

    public record HolderRequest(String name, String email) {}

    /** Optional structured reason, recorded on the license (revoke) and in the audit trail. */
    public record ReasonRequest(String reason) {}

    public record LicenseListResponse(List<LicenseSummaryView> items, int page, int size, long total) {}

    /** Row shape for the list endpoint — deliberately excludes {@code signedToken}. */
    public record LicenseSummaryView(
            UUID id,
            String keyId,
            UUID productId,
            String status,
            String holderName,
            String holderEmail,
            int maxSeats,
            long activeSeats,
            OffsetDateTime issuedAt,
            OffsetDateTime expiresAt,
            String externalRef) {

        static LicenseSummaryView of(License l, long activeSeats) {
            return new LicenseSummaryView(
                    l.getId(),
                    l.getKeyId(),
                    l.getProduct().getId(),
                    l.getStatus().wire(),
                    l.getHolderName(),
                    l.getHolderEmail(),
                    l.getMaxSeats(),
                    activeSeats,
                    l.getIssuedAt(),
                    l.getExpiresAt(),
                    l.getExternalRef());
        }
    }

    /** The detail view — the one place {@code signedToken} is returned back to an admin. */
    public record LicenseDetailView(
            UUID id,
            String keyId,
            UUID productId,
            UUID policyId,
            String status,
            String holderName,
            String holderEmail,
            Map<String, Object> entitlements,
            Map<String, Object> constraints,
            int maxSeats,
            String signedToken,
            String revocationReason,
            OffsetDateTime issuedAt,
            OffsetDateTime activatedAt,
            OffsetDateTime expiresAt,
            OffsetDateTime suspendedAt,
            OffsetDateTime revokedAt,
            String externalRef,
            List<ActivationView> activations) {

        static LicenseDetailView of(License l, List<MachineActivation> licenseActivations) {
            return new LicenseDetailView(
                    l.getId(),
                    l.getKeyId(),
                    l.getProduct().getId(),
                    l.getPolicy().getId(),
                    l.getStatus().wire(),
                    l.getHolderName(),
                    l.getHolderEmail(),
                    l.getEntitlements(),
                    l.getConstraints(),
                    l.getMaxSeats(),
                    l.getSignedToken(),
                    l.getRevocationReason(),
                    l.getIssuedAt(),
                    l.getActivatedAt(),
                    l.getExpiresAt(),
                    l.getSuspendedAt(),
                    l.getRevokedAt(),
                    l.getExternalRef(),
                    licenseActivations.stream().map(ActivationView::of).toList());
        }
    }

    public record ActivationView(
            UUID id,
            String fingerprint,
            String machineName,
            String platform,
            String status,
            OffsetDateTime activatedAt,
            OffsetDateTime lastHeartbeatAt,
            OffsetDateTime deactivatedAt) {

        static ActivationView of(MachineActivation a) {
            return new ActivationView(
                    a.getId(),
                    a.getFingerprint(),
                    a.getMachineName(),
                    a.getPlatform(),
                    a.getStatus(),
                    a.getActivatedAt(),
                    a.getLastHeartbeatAt(),
                    a.getDeactivatedAt());
        }
    }

    /** The 201 response: the short online key id, the full signed token, status, and expiry. */
    public record IssuedLicenseResponse(String keyId, String token, String status, OffsetDateTime expiresAt) {

        static IssuedLicenseResponse of(IssuedLicense issued) {
            return new IssuedLicenseResponse(
                    issued.keyId(), issued.token(), issued.status().wire(), issued.expiresAt());
        }
    }

    public record LifecycleResponse(
            UUID id, String keyId, String status, OffsetDateTime suspendedAt, OffsetDateTime revokedAt, String reason) {

        static LifecycleResponse of(LifecycleResult r) {
            return new LifecycleResponse(r.id(), r.keyId(), r.status(), r.suspendedAt(), r.revokedAt(), r.reason());
        }
    }
}
