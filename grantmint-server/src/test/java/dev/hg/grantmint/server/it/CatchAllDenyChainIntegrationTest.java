package dev.hg.grantmint.server.it;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
