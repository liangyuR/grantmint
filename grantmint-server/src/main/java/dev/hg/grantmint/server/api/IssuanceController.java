package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.issuance.IssuanceCommand;
import dev.hg.grantmint.server.issuance.IssuanceService;
import dev.hg.grantmint.server.issuance.IssuedLicense;
import dev.hg.grantmint.server.security.ApiKeyAuthentication;
import jakarta.servlet.http.HttpServletRequest;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The issuance surface — {@code POST /issuance/licenses}, guarded by the per-product issuance API
 * key (Scheme 2, {@code SCOPE_ISSUE}). The authenticated key's product scope drives the cross-product
 * guard: the controller never trusts a product id from the body, only the one bound to the key. See
 * docs/features/ADMIN_AND_API_AUTH.md and docs/architecture/ARCHITECTURE.md (the issuance flow).
 */
@RestController
@RequestMapping("/issuance")
public class IssuanceController {

    private final IssuanceService issuance;

    public IssuanceController(IssuanceService issuance) {
        this.issuance = issuance;
    }

    @PostMapping("/licenses")
    ResponseEntity<IssuedLicenseResponse> issue(
            @RequestBody IssueLicenseRequest request, Authentication authentication, HttpServletRequest httpRequest) {
        if (request.policyId() == null) {
            throw new IllegalArgumentException("policyId is required");
        }
        if (request.holder() == null) {
            throw new IllegalArgumentException("holder is required");
        }
        ApiKeyAuthentication key = (ApiKeyAuthentication) authentication;
        IssuanceCommand command = new IssuanceCommand(
                key.productId(),
                request.policyId(),
                request.holder().name(),
                request.holder().email(),
                request.expiresAt(),
                request.seat(),
                request.externalRef(),
                key.apiKeyId() == null ? null : key.apiKeyId().toString(),
                httpRequest.getRemoteAddr());
        IssuedLicense issued = issuance.issue(command);
        return ResponseEntity.status(HttpStatus.CREATED).body(IssuedLicenseResponse.of(issued));
    }

    /**
     * @param policyId the tier to mint from (required)
     * @param holder the licensee (required)
     * @param expiresAt overrides the policy duration when set; null uses the policy
     * @param seat overrides the policy seat count when set
     * @param externalRef optional billing reference (e.g. a Stripe subscription id)
     */
    public record IssueLicenseRequest(
            UUID policyId, HolderRequest holder, OffsetDateTime expiresAt, Integer seat, String externalRef) {}

    public record HolderRequest(String name, String email) {}

    /** The 201 response: the short online key id, the full signed token, status, and expiry. */
    public record IssuedLicenseResponse(String keyId, String token, String status, OffsetDateTime expiresAt) {

        static IssuedLicenseResponse of(IssuedLicense issued) {
            return new IssuedLicenseResponse(
                    issued.keyId(), issued.token(), issued.status().wire(), issued.expiresAt());
        }
    }
}
