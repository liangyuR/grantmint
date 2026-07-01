package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.lifecycle.LicenseLifecycleService;
import dev.hg.grantmint.server.lifecycle.LicenseLifecycleService.LifecycleResult;
import dev.hg.grantmint.server.security.ApiKeyAuthentication;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The license lifecycle actions — suspend / reinstate / revoke — on the issuance chain (Scheme 2),
 * gated per-method: these three require {@code SCOPE_REVOKE}, so a future issue-only credential
 * cannot kill licenses. Legality lives in the core state machine; an illegal move (reinstating a
 * revoked license) is a 409 {@code invalid_state_transition}. These actions affect <b>online</b>
 * validation immediately (the cache entry is evicted on commit); already-distributed offline tokens
 * keep verifying until their exp — the honest offline-revocation limitation. See
 * docs/api/API_DOCUMENTATION.md (license lifecycle actions) and docs/features/LICENSE_LIFECYCLE.md.
 */
@RestController
@RequestMapping("/issuance/licenses")
@Tag(name = "License lifecycle", description = "Suspend, reinstate, and revoke licenses (Scheme 2, SCOPE_REVOKE).")
@SecurityRequirement(name = OpenApiConfig.ISSUANCE_KEY)
public class LicenseLifecycleController {

    private final LicenseLifecycleService lifecycle;

    public LicenseLifecycleController(LicenseLifecycleService lifecycle) {
        this.lifecycle = lifecycle;
    }

    @PostMapping("/{keyId}/suspend")
    @Operation(
            summary = "Suspend a license",
            description = "ACTIVE → SUSPENDED (recoverable — e.g. payment failure). Online validation fails "
                    + "immediately with license_suspended; reinstate restores it.")
    @ApiResponses({
        @ApiResponse(
                responseCode = "200",
                description = "License suspended",
                content = @Content(schema = @Schema(implementation = LifecycleResponse.class))),
        @ApiResponse(
                responseCode = "404",
                description = "No license with this key id is visible to the requesting product",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "409",
                description = "Illegal transition (e.g. suspending a revoked or never-activated license)",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
    })
    ResponseEntity<LifecycleResponse> suspend(
            @PathVariable String keyId,
            @RequestBody(required = false) ReasonRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        ApiKeyAuthentication key = (ApiKeyAuthentication) authentication;
        LifecycleResult result = lifecycle.suspend(
                keyId, key.productId(), request == null ? null : request.reason(), actorOf(key), ip(httpRequest));
        return ResponseEntity.ok(LifecycleResponse.of(result));
    }

    @PostMapping("/{keyId}/reinstate")
    @Operation(
            summary = "Reinstate a suspended license",
            description = "SUSPENDED → ACTIVE. Online checks pass again immediately; existing activations resume.")
    @ApiResponses({
        @ApiResponse(
                responseCode = "200",
                description = "License reinstated",
                content = @Content(schema = @Schema(implementation = LifecycleResponse.class))),
        @ApiResponse(
                responseCode = "404",
                description = "No license with this key id is visible to the requesting product",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "409",
                description = "Illegal transition — revocation is terminal, expiry reinstates only via renewal",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
    })
    ResponseEntity<LifecycleResponse> reinstate(
            @PathVariable String keyId, Authentication authentication, HttpServletRequest httpRequest) {
        ApiKeyAuthentication key = (ApiKeyAuthentication) authentication;
        LifecycleResult result = lifecycle.reinstate(keyId, key.productId(), actorOf(key), ip(httpRequest));
        return ResponseEntity.ok(LifecycleResponse.of(result));
    }

    @DeleteMapping("/{keyId}")
    @Operation(
            summary = "Revoke a license (terminal)",
            description = "Any non-revoked state → REVOKED. There is no un-revoke: a disputed revocation is "
                    + "resolved by issuing a new license. The next online validate/heartbeat fails with "
                    + "license_revoked; the offline token keeps verifying until its exp.")
    @ApiResponses({
        @ApiResponse(
                responseCode = "200",
                description = "License revoked",
                content = @Content(schema = @Schema(implementation = LifecycleResponse.class))),
        @ApiResponse(
                responseCode = "404",
                description = "No license with this key id is visible to the requesting product",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "409",
                description = "Already revoked (revocation is terminal)",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
    })
    ResponseEntity<LifecycleResponse> revoke(
            @PathVariable String keyId,
            @RequestBody(required = false) ReasonRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        ApiKeyAuthentication key = (ApiKeyAuthentication) authentication;
        LifecycleResult result = lifecycle.revoke(
                keyId, key.productId(), request == null ? null : request.reason(), actorOf(key), ip(httpRequest));
        return ResponseEntity.ok(LifecycleResponse.of(result));
    }

    private static String actorOf(ApiKeyAuthentication key) {
        UUID apiKeyId = key.apiKeyId();
        return apiKeyId == null ? "api_key" : apiKeyId.toString();
    }

    private static String ip(HttpServletRequest request) {
        return request.getRemoteAddr();
    }

    /** Optional structured reason, recorded on the license (revoke) and in the audit trail. */
    public record ReasonRequest(String reason) {}

    public record LifecycleResponse(
            UUID id, String keyId, String status, OffsetDateTime suspendedAt, OffsetDateTime revokedAt, String reason) {

        static LifecycleResponse of(LifecycleResult r) {
            return new LifecycleResponse(r.id(), r.keyId(), r.status(), r.suspendedAt(), r.revokedAt(), r.reason());
        }
    }
}
