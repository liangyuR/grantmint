package dev.hg.grantmint.server.it;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

/**
 * The declared cross-origin and response-header policy (2026-07 audit, GRANTMINT-168). Before this
 * existed the posture was safe only by omission — no CORS processing, Spring Security's implicit
 * header defaults. Now it is explicit and testable: exact-origin credentialed CORS when an operator
 * configures {@code grantmint.security.cors.allowed-origins} (this context does), everything else
 * rejected, and the security headers asserted on every chain. The companion default — NO CORS
 * headers at all when the property is unset — is pinned in {@link CatchAllDenyChainIntegrationTest}.
 */
@SpringBootTest(properties = "grantmint.security.cors.allowed-origins=https://ops.example.com")
@AutoConfigureMockMvc
@Transactional
class SecurityHeadersAndCorsIntegrationTest extends PostgresIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void everyChainCarriesTheExplicitSecurityHeaders() throws Exception {
        // Admin chain (unauthenticated → 401, but the header policy applies regardless of outcome).
        mockMvc.perform(get("/admin/products"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().exists("Cache-Control"));

        // Catch-all chain: unmatched paths get the same policy, not a bare deny.
        mockMvc.perform(get("/some/unmapped/path"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"));

        // Validation chain (hottest path) is not exempt.
        mockMvc.perform(get("/v1/licenses/anything"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"));
    }

    @Test
    void preflightFromTheConfiguredOriginIsGrantedWithCredentials() throws Exception {
        mockMvc.perform(options("/admin/products")
                        .header("Origin", "https://ops.example.com")
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "X-XSRF-TOKEN"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "https://ops.example.com"))
                .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
    }

    @Test
    void anyUnlistedOriginIsRejectedNeverReflected() throws Exception {
        // Preflight from an unlisted origin: refused, and the origin is never echoed back.
        mockMvc.perform(options("/admin/products")
                        .header("Origin", "https://evil.example.com")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));

        // Actual (non-preflight) cross-origin request from an unlisted origin: same refusal.
        mockMvc.perform(get("/v1/licenses/validate").header("Origin", "https://evil.example.com"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }
}
