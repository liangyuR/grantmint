package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.domain.ApiKey;
import dev.hg.grantmint.server.security.AdminPrincipal;
import dev.hg.grantmint.server.security.ApiKeyEnvironment;
import dev.hg.grantmint.server.security.ApiKeyScope;
import dev.hg.grantmint.server.security.ApiKeyService;
import dev.hg.grantmint.server.security.ApiKeyService.MintedKey;
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
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Admin-only management of per-product issuance and validation keys (Scheme 1 protects these). The
 * secret is returned exactly once at creation; list and revoke never expose it. Every mutation is
 * audited. See docs/features/ADMIN_AND_API_AUTH.md.
 */
@RestController
@RequestMapping("/admin/products/{productId}")
@Tag(name = "API keys (admin)", description = "Manage a product's issuance and validation keys; secret shown once.")
@SecurityRequirement(name = OpenApiConfig.ADMIN_SESSION)
public class ApiKeyAdminController {

    private final ApiKeyService apiKeys;
    private final AuditService audit;

    public ApiKeyAdminController(ApiKeyService apiKeys, AuditService audit) {
        this.apiKeys = apiKeys;
        this.audit = audit;
    }

    @PostMapping("/issuance-keys")
    @Operation(summary = "Create an issuance key", description = "Returns the plaintext secret exactly once.")
    ResponseEntity<CreatedApiKey> createIssuanceKey(
            @PathVariable UUID productId,
            @RequestBody CreateApiKeyRequest request,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        return create(
                productId,
                ApiKeyScope.ISSUANCE,
                ApiKeyEnvironment.fromToken(request.environment()),
                request.name(),
                admin,
                httpRequest);
    }

    @GetMapping("/issuance-keys")
    @Operation(summary = "List issuance keys (metadata only)")
    List<ApiKeyView> listIssuanceKeys(@PathVariable UUID productId) {
        return list(productId, ApiKeyScope.ISSUANCE);
    }

    @DeleteMapping("/issuance-keys/{keyId}")
    @Operation(summary = "Revoke an issuance key")
    ResponseEntity<Void> revokeIssuanceKey(
            @PathVariable UUID productId,
            @PathVariable UUID keyId,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        return revoke(productId, keyId, admin, httpRequest);
    }

    @PostMapping("/validation-keys")
    @Operation(summary = "Create a validation key", description = "Returns the plaintext secret exactly once.")
    ResponseEntity<CreatedApiKey> createValidationKey(
            @PathVariable UUID productId,
            @RequestBody CreateApiKeyRequest request,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        return create(productId, ApiKeyScope.VALIDATION, ApiKeyEnvironment.LIVE, request.name(), admin, httpRequest);
    }

    @GetMapping("/validation-keys")
    @Operation(summary = "List validation keys (metadata only)")
    List<ApiKeyView> listValidationKeys(@PathVariable UUID productId) {
        return list(productId, ApiKeyScope.VALIDATION);
    }

    @DeleteMapping("/validation-keys/{keyId}")
    @Operation(summary = "Revoke a validation key")
    ResponseEntity<Void> revokeValidationKey(
            @PathVariable UUID productId,
            @PathVariable UUID keyId,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        return revoke(productId, keyId, admin, httpRequest);
    }

    private ResponseEntity<CreatedApiKey> create(
            UUID productId,
            ApiKeyScope scope,
            ApiKeyEnvironment environment,
            String name,
            AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        MintedKey minted = apiKeys.createProductKey(productId, scope, environment, name);
        ApiKey key = minted.apiKey();
        audit.record(
                admin.username(),
                AuditActorType.ADMIN,
                "apikey.created",
                "api_key",
                key.getId().toString(),
                Map.of("scope", scope.wire(), "product_id", productId.toString()),
                httpRequest.getRemoteAddr());
        CreatedApiKey body = new CreatedApiKey(
                key.getId(),
                key.getName(),
                productId,
                scope.wire(),
                key.getKeyPrefix(),
                minted.plaintext(),
                key.getCreatedAt(),
                "Store this secret now. It will not be shown again.");
        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }

    private List<ApiKeyView> list(UUID productId, ApiKeyScope scope) {
        return apiKeys.listForProduct(productId).stream()
                .filter(k -> scope.wire().equals(k.getScope()))
                .map(ApiKeyView::of)
                .toList();
    }

    private ResponseEntity<Void> revoke(
            UUID productId, UUID keyId, AdminPrincipal admin, HttpServletRequest httpRequest) {
        apiKeys.revoke(productId, keyId);
        audit.record(
                admin.username(),
                AuditActorType.ADMIN,
                "apikey.revoked",
                "api_key",
                keyId.toString(),
                Map.of("product_id", productId.toString()),
                httpRequest.getRemoteAddr());
        return ResponseEntity.noContent().build();
    }

    /**
     * @param name a descriptive label for the key
     * @param environment {@code live} or {@code test} (issuance keys only; ignored otherwise)
     */
    public record CreateApiKeyRequest(String name, String environment) {}

    /** The one-time creation response; {@code secret} is never recoverable after this. */
    public record CreatedApiKey(
            UUID id,
            String name,
            UUID productId,
            String scope,
            String keyPrefix,
            String secret,
            OffsetDateTime createdAt,
            String warning) {}

    /** Metadata view of a key — never carries the secret or its hash. */
    public record ApiKeyView(
            UUID id,
            String name,
            String scope,
            String keyPrefix,
            OffsetDateTime createdAt,
            OffsetDateTime lastUsedAt,
            OffsetDateTime expiresAt,
            OffsetDateTime revokedAt,
            boolean active) {

        static ApiKeyView of(ApiKey key) {
            return new ApiKeyView(
                    key.getId(),
                    key.getName(),
                    key.getScope(),
                    key.getKeyPrefix(),
                    key.getCreatedAt(),
                    key.getLastUsedAt(),
                    key.getExpiresAt(),
                    key.getRevokedAt(),
                    key.getRevokedAt() == null);
        }
    }
}
