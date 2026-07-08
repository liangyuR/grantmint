package dev.hg.grantmint.server.it;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

/**
 * The catch-all default-deny chain (2026-07-05 audit, GRANTMINT-146): a request outside every
 * scoped chain is denied — a future controller added under an unlisted prefix is closed until
 * someone deliberately opens it — while the two deliberate pass-throughs keep working: webhooks
 * (HMAC-authenticated in the controller) and the actuator (loopback-bound management port).
 */
@SpringBootTest(
        properties = {
            "grantmint.webhooks.stripe.enabled=true",
            "grantmint.webhooks.stripe.signing-secret=whsec_test_secret_1234567890", // gitleaks:allow fake test secret
        })
@AutoConfigureMockMvc
@Transactional
class CatchAllDenyChainIntegrationTest extends PostgresIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void requestOutsideEveryScopedChainIsDeniedNotSilentlyOpen() throws Exception {
        mockMvc.perform(get("/some/future/endpoint"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("unauthorized"));

        mockMvc.perform(post("/internal/debug")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isUnauthorized());

        // A direct external hit on Boot's /error rendering path is a plain REQUEST dispatch —
        // denied; only the container's internal ERROR re-dispatch is permitted.
        mockMvc.perform(get("/error")).andExpect(status().isUnauthorized());
    }

    @Test
    void corsStaysDisabledByDefaultWhileTheExplicitHeaderPolicyApplies() throws Exception {
        // No grantmint.security.cors.allowed-origins in this context (the shipped default): a
        // cross-origin request gets NO CORS headers back — browsers enforce same-origin — while
        // the explicit response-header policy still applies (2026-07 audit, GRANTMINT-168).
        // SecurityHeadersAndCorsIntegrationTest pins the configured-origins behavior.
        mockMvc.perform(get("/admin/products").header("Origin", "https://anywhere.example.com"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"));
    }

    @Test
    void mainPortNeverServesActuatorContent() throws Exception {
        // The actuator rides its own loopback-bound management container (port 9090,
        // application.yml); the catch-all's /actuator/** pass-through exists only so that split
        // stays inert. The main servlet context must have NO actuator handler mapped — a 404 here,
        // never a 200 with health or metrics content (post-M13 audit: this boundary was real but
        // untested).
        mockMvc.perform(get("/actuator/health")).andExpect(status().isNotFound());
        mockMvc.perform(get("/actuator/prometheus")).andExpect(status().isNotFound());
        mockMvc.perform(get("/actuator")).andExpect(status().isNotFound());
    }

    @Test
    void webhookSurfaceStillReachesItsHmacVerifyingController() throws Exception {
        // Unsigned delivery: the catch-all chain must hand the request through to the controller,
        // whose signature verification rejects it as 400 — NOT a 401 from the deny-all rule (that
        // would mean the chain swallowed the webhook surface) and NOT a 2xx (unsigned must fail).
        mockMvc.perform(post("/webhooks/stripe")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"id\":\"evt_unsigned\",\"type\":\"checkout.session.completed\"}"))
                .andExpect(status().isBadRequest());
    }
}
