package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.activation.ActivationCommand;
import dev.hg.grantmint.server.activation.ActivationResult;
import dev.hg.grantmint.server.activation.ActivationService;
import dev.hg.grantmint.server.activation.DeactivationResult;
import dev.hg.grantmint.server.activation.HeartbeatResult;
import dev.hg.grantmint.server.security.ApiKeyAuthentication;
import dev.hg.grantmint.server.validation.ClientIpResolver;
import dev.hg.grantmint.server.validation.ValidationRateLimiter;
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
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The node-locked activation surface — {@code POST /v1/licenses/activate|deactivate|heartbeat},
 * guarded by the same low-privilege validation key (Scheme 3) and rate limiter as {@code /validate}.
 * The key is product-scoped, so its product id flows down for the cross-product guard; the license
 * key id travels in the body, mirroring the validate contract. See
 * docs/features/ACTIVATION_AND_SEATS.md and docs/api/API_DOCUMENTATION.md.
 */
@RestController
@RequestMapping("/v1/licenses")
@Tag(
        name = "Activation",
        description = "Node-locked device activation, seat release, and heartbeats (Scheme 3, validation key).")
@SecurityRequirement(name = OpenApiConfig.VALIDATION_KEY)
public class ActivationController {

    private final ActivationService activation;
    private final ValidationRateLimiter rateLimiter;
    private final ClientIpResolver clientIp;

    public ActivationController(
            ActivationService activation, ValidationRateLimiter rateLimiter, ClientIpResolver clientIp) {
        this.activation = activation;
        this.rateLimiter = rateLimiter;
        this.clientIp = clientIp;
    }

    @PostMapping("/activate")
    @Operation(
            summary = "Activate a device (claim a seat)",
            description = "Binds a machine fingerprint to the license, consuming one seat. Idempotent per "
                    + "fingerprint: re-activating an already-active device returns 200 without consuming a second "
                    + "seat, so clients may call this on every launch. The first activation transitions a CREATED "
                    + "license to ACTIVE.")
    @ApiResponses({
        @ApiResponse(
                responseCode = "201",
                description = "Seat claimed for a new fingerprint",
                content = @Content(schema = @Schema(implementation = ActivateResponse.class))),
        @ApiResponse(
                responseCode = "200",
                description = "Fingerprint already held a seat — idempotent, no new seat consumed",
                content = @Content(schema = @Schema(implementation = ActivateResponse.class))),
        @ApiResponse(
                responseCode = "400",
                description = "keyId or fingerprint missing/invalid",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "404",
                description = "No license with this key id is visible to the requesting product",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "409",
                description = "Seat limit exceeded — all seats held by other fingerprints",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "422",
                description = "License cannot be activated (revoked / suspended / expired / not-yet-valid)",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "429",
                description = "Rate limit exceeded; retry after the Retry-After header",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
    })
    ResponseEntity<ActivateResponse> activate(
            @RequestBody ActivateRequest request, Authentication authentication, HttpServletRequest httpRequest) {
        String keyId = requireKeyId(request == null ? null : request.keyId());
        String ip = clientIp.resolve(httpRequest);
        rateLimiter.check(keyId, ip);
        ApiKeyAuthentication key = (ApiKeyAuthentication) authentication;
        ActivationResult result = activation.activate(new ActivationCommand(
                keyId,
                key.productId(),
                request.fingerprint(),
                request.name(),
                request.platform(),
                request.metadata(),
                actorOf(key),
                ip));
        return ResponseEntity.status(result.reactivated() ? HttpStatus.OK : HttpStatus.CREATED)
                .body(ActivateResponse.of(result));
    }

    @PostMapping("/deactivate")
    @Operation(
            summary = "Deactivate a device (free a seat)",
            description = "Releases the seat held by a fingerprint so another device can activate — the "
                    + "\"moving to a new laptop\" flow. Always allowed regardless of license health; the seat "
                    + "count never goes negative.")
    @ApiResponses({
        @ApiResponse(
                responseCode = "200",
                description = "Seat released",
                content = @Content(schema = @Schema(implementation = DeactivateResponse.class))),
        @ApiResponse(
                responseCode = "400",
                description = "keyId or fingerprint missing/invalid",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "404",
                description = "License not visible to this product, or no active seat for this fingerprint",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "429",
                description = "Rate limit exceeded; retry after the Retry-After header",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
    })
    ResponseEntity<DeactivateResponse> deactivate(
            @RequestBody DeactivateRequest request, Authentication authentication, HttpServletRequest httpRequest) {
        String keyId = requireKeyId(request == null ? null : request.keyId());
        String ip = clientIp.resolve(httpRequest);
        rateLimiter.check(keyId, ip);
        ApiKeyAuthentication key = (ApiKeyAuthentication) authentication;
        DeactivationResult result =
                activation.deactivate(keyId, key.productId(), request.fingerprint(), actorOf(key), ip);
        return ResponseEntity.ok(DeactivateResponse.of(result));
    }

    @PostMapping("/heartbeat")
    @Operation(
            summary = "Heartbeat (keep a seat alive)",
            description = "Refreshes the activation's last_heartbeat_at, keeping the seat from the timeout "
                    + "reaper. Also the moment a previously-offline device learns its license was revoked or "
                    + "suspended (422).")
    @ApiResponses({
        @ApiResponse(
                responseCode = "200",
                description = "Heartbeat recorded; next check-in deadline returned",
                content = @Content(schema = @Schema(implementation = HeartbeatResponse.class))),
        @ApiResponse(
                responseCode = "400",
                description = "keyId or fingerprint missing/invalid",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "404",
                description = "License not visible to this product, or no active seat for this fingerprint "
                        + "(client should re-activate)",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "422",
                description = "License revoked / suspended / expired — stop granting entitlements",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
        @ApiResponse(
                responseCode = "429",
                description = "Rate limit exceeded; retry after the Retry-After header",
                content = @Content(schema = @Schema(implementation = ApiError.class))),
    })
    ResponseEntity<HeartbeatResponse> heartbeat(
            @RequestBody HeartbeatRequest request, Authentication authentication, HttpServletRequest httpRequest) {
        String keyId = requireKeyId(request == null ? null : request.keyId());
        rateLimiter.check(keyId, clientIp.resolve(httpRequest));
        ApiKeyAuthentication key = (ApiKeyAuthentication) authentication;
        HeartbeatResult result = activation.heartbeat(keyId, key.productId(), request.fingerprint());
        return ResponseEntity.ok(HeartbeatResponse.of(result));
    }

    private static String requireKeyId(String keyId) {
        if (keyId == null || keyId.isBlank()) {
            throw new IllegalArgumentException("keyId is required");
        }
        return keyId;
    }

    private static String actorOf(ApiKeyAuthentication key) {
        UUID apiKeyId = key.apiKeyId();
        return apiKeyId == null ? "api_key" : apiKeyId.toString();
    }

    /**
     * @param keyId the license key id (required)
     * @param fingerprint the opaque client-computed device fingerprint (required)
     * @param name optional human-readable device label, dashboard-only
     * @param platform optional platform hint, e.g. {@code macos}
     * @param metadata optional free-form dashboard metadata; never affects seat counting
     */
    public record ActivateRequest(
            String keyId, String fingerprint, String name, String platform, Map<String, Object> metadata) {}

    public record DeactivateRequest(String keyId, String fingerprint) {}

    public record HeartbeatRequest(String keyId, String fingerprint) {}

    /** The 200/201 activation response; {@code reactivated} marks the idempotent re-claim path. */
    public record ActivateResponse(
            String keyId,
            UUID activationId,
            String fingerprint,
            String status,
            boolean reactivated,
            long seatsUsed,
            int seatsTotal,
            OffsetDateTime activatedAt,
            int heartbeatIntervalSeconds,
            OffsetDateTime nextHeartbeatDueBy) {

        static ActivateResponse of(ActivationResult r) {
            return new ActivateResponse(
                    r.keyId(),
                    r.activationId(),
                    r.fingerprint(),
                    r.machineStatus(),
                    r.reactivated(),
                    r.seatsUsed(),
                    r.seatsTotal(),
                    r.activatedAt(),
                    r.heartbeatIntervalSeconds(),
                    r.nextHeartbeatDueBy());
        }
    }

    public record DeactivateResponse(
            String keyId,
            String fingerprint,
            boolean deactivated,
            long seatsUsed,
            int seatsTotal,
            OffsetDateTime deactivatedAt) {

        static DeactivateResponse of(DeactivationResult r) {
            return new DeactivateResponse(
                    r.keyId(), r.fingerprint(), true, r.seatsUsed(), r.seatsTotal(), r.deactivatedAt());
        }
    }

    public record HeartbeatResponse(
            String keyId,
            String fingerprint,
            String licenseStatus,
            String machineStatus,
            OffsetDateTime lastHeartbeatAt,
            OffsetDateTime nextHeartbeatDueBy) {

        static HeartbeatResponse of(HeartbeatResult r) {
            return new HeartbeatResponse(
                    r.keyId(),
                    r.fingerprint(),
                    r.licenseStatus(),
                    r.machineStatus(),
                    r.lastHeartbeatAt(),
                    r.nextHeartbeatDueBy());
        }
    }
}
