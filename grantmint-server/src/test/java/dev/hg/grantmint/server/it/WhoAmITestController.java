package dev.hg.grantmint.server.it;

import dev.hg.grantmint.server.security.AdminPrincipal;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Test-only endpoints mounted under each secured prefix so the integration tests can assert what an
 * authenticated request actually carries (principal + authorities). The real business endpoints for
 * these prefixes land in M4 (issuance) and M5 (validation); until then these stand in to exercise
 * the M3 auth chains end-to-end.
 */
@RestController
class WhoAmITestController {

    /** Reached only with SCOPE_ISSUE/SCOPE_REVOKE (issuance chain) — echoes the scoped product id. */
    @GetMapping("/issuance/whoami")
    Map<String, Object> issuanceWhoAmI(Authentication authentication) {
        return apiKeyIdentity(authentication);
    }

    /** Reached only with SCOPE_VALIDATION (validation chain) — echoes the scoped product id. */
    @GetMapping("/v1/licenses/whoami")
    Map<String, Object> validationWhoAmI(Authentication authentication) {
        return apiKeyIdentity(authentication);
    }

    /** Reached only with ROLE_ADMIN (admin chain) — echoes the operator username. */
    @GetMapping("/admin/whoami")
    Map<String, Object> adminWhoAmI(Authentication authentication) {
        AdminPrincipal principal = (AdminPrincipal) authentication.getPrincipal();
        return Map.of("username", principal.username(), "authorities", authorities(authentication));
    }

    private Map<String, Object> apiKeyIdentity(Authentication authentication) {
        return Map.of(
                "productId", String.valueOf(authentication.getPrincipal()), "authorities", authorities(authentication));
    }

    private List<String> authorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .sorted()
                .toList();
    }
}
