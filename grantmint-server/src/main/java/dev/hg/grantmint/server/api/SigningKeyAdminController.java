package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.domain.SigningKey;
import dev.hg.grantmint.server.security.AdminPrincipal;
import dev.hg.grantmint.server.signing.SigningKeyException;
import dev.hg.grantmint.server.signing.SigningKeyService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Admin-only registration and listing of a product's Ed25519 signing keys (Scheme 1 protects
 * these). {@link SigningKeyService#register} proves the supplied public key matches the private
 * seed behind {@code privateKeyRef} before anything is persisted — only the public half and the ref
 * pointer are ever stored or returned. Every registration is audited. See
 * docs/architecture/ARCHITECTURE.md (the issuance flow).
 */
@RestController
@RequestMapping("/admin/products/{productId}/signing-keys")
@Tag(name = "Signing keys (admin)", description = "Register and list a product's Ed25519 signing keys.")
@SecurityRequirement(name = OpenApiConfig.ADMIN_SESSION)
public class SigningKeyAdminController {

    private final SigningKeyService signingKeys;
    private final AuditService audit;

    public SigningKeyAdminController(SigningKeyService signingKeys, AuditService audit) {
        this.signingKeys = signingKeys;
        this.audit = audit;
    }

    @PostMapping
    @Operation(
            summary = "Register a signing key",
            description = "Proves the public key matches the private seed behind privateKeyRef before persisting.")
    ResponseEntity<SigningKeyView> register(
            @PathVariable UUID productId,
            @RequestBody RegisterSigningKeyRequest request,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        byte[] rawPublicKey = Base64.getDecoder().decode(request.publicKey());
        SigningKey key = signingKeys.register(
                productId, request.keyId(), request.privateKeyRef(), rawPublicKey, request.makeActive());
        audit.record(
                admin.username(),
                AuditActorType.ADMIN,
                "signingkey.registered",
                "signing_key",
                key.getKeyId(),
                Map.of("product_id", productId.toString(), "make_active", String.valueOf(request.makeActive())),
                httpRequest.getRemoteAddr());
        return ResponseEntity.status(HttpStatus.CREATED).body(SigningKeyView.of(key));
    }

    @GetMapping
    @Operation(summary = "List a product's signing keys (public key + pointer metadata only)")
    List<SigningKeyView> list(@PathVariable UUID productId) {
        return signingKeys.listForProduct(productId).stream()
                .map(SigningKeyView::of)
                .toList();
    }

    /**
     * A registration the service refused — wrong key length, an unresolvable {@code
     * private_key_ref}, or a public key that does not match the seed behind the ref. Deliberately a
     * controller-LOCAL handler, not one in {@link ApiExceptionHandler}: at registration time these
     * are caller input problems (400), but the same {@link SigningKeyException} is also thrown when
     * issuance resolves the seed at signing time, and there it is a server-side operational failure
     * that must surface as a 500 — a global 400 mapping would tell an issuance client its request
     * was malformed when actually the operator's key ref broke.
     */
    @ExceptionHandler(SigningKeyException.class)
    ResponseEntity<ApiError> handleRejectedRegistration(SigningKeyException ex) {
        return ResponseEntity.badRequest().body(new ApiError("bad_request", ex.getMessage()));
    }

    /**
     * @param keyId the short signing-key id (the token header {@code kid})
     * @param privateKeyRef pointer to the private seed (e.g. {@code file:...}, {@code env:...})
     * @param publicKey STANDARD base64 of the raw 32-byte Ed25519 public key
     * @param makeActive whether this key becomes the product's active signing key
     */
    public record RegisterSigningKeyRequest(String keyId, String privateKeyRef, String publicKey, boolean makeActive) {}

    /** Metadata view of a signing key — public key only, never private bytes. */
    public record SigningKeyView(
            String keyId,
            UUID productId,
            String algorithm,
            String publicKey,
            String privateKeyRef,
            String status,
            OffsetDateTime createdAt) {

        static SigningKeyView of(SigningKey key) {
            return new SigningKeyView(
                    key.getKeyId(),
                    key.getProduct().getId(),
                    key.getAlgorithm(),
                    Base64.getEncoder().encodeToString(key.getPublicKey()),
                    key.getPrivateKeyRef(),
                    key.getStatus(),
                    key.getCreatedAt());
        }
    }
}
