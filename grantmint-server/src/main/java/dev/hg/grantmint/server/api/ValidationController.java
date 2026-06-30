package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.security.ApiKeyAuthentication;
import dev.hg.grantmint.server.validation.ValidationRateLimiter;
import dev.hg.grantmint.server.validation.ValidationService;
import dev.hg.grantmint.server.validation.ValidationView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.time.OffsetDateTime;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The online validation surface — {@code POST /v1/licenses/validate}, guarded by the low-privilege
 * validation key (Scheme 3, {@code X-Grantmint-Validation} → {@code SCOPE_VALIDATION}). The key is
 * product-scoped, so the controller passes its product id down for the cross-product guard and never
 * trusts a product hint from the body.
 *
 * <p>A healthy license returns {@code 200} with {@code valid: true} and its live entitlements; an
 * authentic-but-unusable one (revoked/suspended/expired/…) returns {@code 422} with {@code valid:
 * false} semantics via the error envelope; missing or wrong credentials are rejected as {@code
 * 401}/{@code 403} by the security chain before reaching here. See docs/api/API_DOCUMENTATION.md.
 */
@RestController
@RequestMapping("/v1/licenses")
@Tag(name = "Validation", description = "Validate a license online with a low-privilege validation key (Scheme 3).")
@SecurityRequirement(name = OpenApiConfig.VALIDATION_KEY)
public class ValidationController {

    private final ValidationService validation;
    private final ValidationRateLimiter rateLimiter;

    public ValidationController(ValidationService validation, ValidationRateLimiter rateLimiter) {
        this.validation = validation;
        this.rateLimiter = rateLimiter;
    }

    @PostMapping("/validate")
    @Operation(
            summary = "Validate a license",
            description = "Runs the full online check — token signature, database status (revocation/suspension), and "
                    + "temporal window (nbf/exp) — and returns the live entitlements. Returns 422 with valid:false "
                    + "for an unhealthy license, or 429 with Retry-After when the per-key/per-IP rate limit is "
                    + "exceeded.")
    @ApiResponses({
        @ApiResponse(
                responseCode = "200",
                description = "License is valid; live entitlements returned",
                content = @Content(schema = @Schema(implementation = ValidateResponse.class))),
        @ApiResponse(
                responseCode = "400",
                description = "keyId missing or blank",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "401",
                description = "Missing or unrecognized validation credential",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "403",
                description = "Credential lacks the validation scope",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "404",
                description = "No license with this key id is visible to the requesting product",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "422",
                description = "Authentic but unusable license (revoked / suspended / expired / not-yet-valid / "
                        + "inactive) — valid:false with a stable reason code",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "429",
                description = "Per-key or per-IP rate limit exceeded; retry after the Retry-After header",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
    })
    ResponseEntity<ValidateResponse> validate(
            @RequestBody ValidateRequest request, Authentication authentication, HttpServletRequest httpRequest) {
        if (request == null || request.keyId() == null || request.keyId().isBlank()) {
            throw new IllegalArgumentException("keyId is required");
        }
        rateLimiter.check(request.keyId(), httpRequest.getRemoteAddr());
        ApiKeyAuthentication key = (ApiKeyAuthentication) authentication;
        ValidationView view = validation.validate(request.keyId(), key.productId(), request.fingerprint());
        return ResponseEntity.ok(ValidateResponse.of(view));
    }

    /**
     * @param keyId the license key id to validate (required)
     * @param fingerprint the optional machine fingerprint; accepted now, matched against an activation
     *     in M6
     */
    public record ValidateRequest(String keyId, String fingerprint) {}

    /** The 200 response: always {@code valid:true} here (failures surface as 422 error bodies). */
    public record ValidateResponse(
            boolean valid,
            String status,
            String keyId,
            OffsetDateTime expiresAt,
            Map<String, Object> entitlements,
            OffsetDateTime checkedAt) {

        static ValidateResponse of(ValidationView view) {
            return new ValidateResponse(
                    true, view.status(), view.keyId(), view.expiresAt(), view.entitlements(), view.checkedAt());
        }
    }
}
