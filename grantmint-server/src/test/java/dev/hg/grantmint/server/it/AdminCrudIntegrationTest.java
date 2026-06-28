package dev.hg.grantmint.server.it;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.grantmint.server.security.AdminUserService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

/**
 * Integration tests for the M4 admin CRUD endpoints (products, policies, entitlements). Exercises
 * the full Spring stack against real PostgreSQL. Verifies:
 *
 * <ul>
 *   <li>Unauthenticated requests are rejected with 401.
 *   <li>Create product → create policy → add entitlements → policy snapshot reflects them.
 *   <li>Updating an entitlement rebuilds the snapshot correctly.
 *   <li>Deleting an entitlement drops it from the snapshot.
 *   <li>Basic product list / get / delete path.
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AdminCrudIntegrationTest extends PostgresIntegrationTest {

    private static final String ADMIN_USERNAME = "crudadmin";
    private static final String ADMIN_PASSWORD = "battery-staple-correct-horse";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AdminUserService adminUsers;

    @Autowired
    private ObjectMapper objectMapper;

    private String adminSessionToken() throws Exception {
        adminUsers.bootstrapIfEmpty(ADMIN_USERNAME, ADMIN_PASSWORD);
        MvcResult result = mockMvc.perform(post("/admin/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + ADMIN_USERNAME + "\",\"password\":\"" + ADMIN_PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andReturn();
        return objectMapper
                .readTree(result.getResponse().getContentAsString())
                .get("token")
                .asText();
    }

    @Test
    void unauthenticatedRequestToProductsIs401() throws Exception {
        mockMvc.perform(get("/admin/products")).andExpect(status().isUnauthorized());
    }

    @Test
    void fullCrudLifecycle() throws Exception {
        String token = adminSessionToken();

        // ─── Create product ───────────────────────────────────────────────────
        MvcResult createProductResult = mockMvc.perform(post("/admin/products")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"acme-app\",\"name\":\"Acme App\",\"description\":\"Test product\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.slug").value("acme-app"))
                .andExpect(jsonPath("$.name").value("Acme App"))
                .andReturn();

        UUID productId = UUID.fromString(objectMapper
                .readTree(createProductResult.getResponse().getContentAsString())
                .get("id")
                .asText());

        // ─── Create policy ────────────────────────────────────────────────────
        MvcResult createPolicyResult = mockMvc.perform(post("/admin/products/" + productId + "/policies")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"pro\",\"name\":\"Pro Tier\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.code").value("pro"))
                .andExpect(jsonPath("$.productId").value(productId.toString()))
                .andExpect(jsonPath("$.entitlements").isMap())
                .andReturn();

        UUID policyId = UUID.fromString(objectMapper
                .readTree(createPolicyResult.getResponse().getContentAsString())
                .get("id")
                .asText());

        // ─── Add flag entitlement ─────────────────────────────────────────────
        MvcResult createFlagResult = mockMvc.perform(post("/admin/policies/" + policyId + "/entitlements")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"team_sync\",\"valueType\":\"flag\",\"value\":true}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.code").value("team_sync"))
                .andExpect(jsonPath("$.valueType").value("flag"))
                .andReturn();

        UUID flagEntitlementId = UUID.fromString(objectMapper
                .readTree(createFlagResult.getResponse().getContentAsString())
                .get("id")
                .asText());

        // ─── Add limit entitlement ────────────────────────────────────────────
        MvcResult createLimitResult = mockMvc.perform(post("/admin/policies/" + policyId + "/entitlements")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"max_devices\",\"valueType\":\"limit\",\"value\":5}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.code").value("max_devices"))
                .andExpect(jsonPath("$.valueType").value("limit"))
                .andReturn();

        UUID limitEntitlementId = UUID.fromString(objectMapper
                .readTree(createLimitResult.getResponse().getContentAsString())
                .get("id")
                .asText());

        // ─── GET policy: snapshot contains both entitlements ──────────────────
        mockMvc.perform(get("/admin/policies/" + policyId).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.entitlements.team_sync").value(true))
                .andExpect(jsonPath("$.entitlements.max_devices").value(5));

        // ─── Update limit entitlement ─────────────────────────────────────────
        mockMvc.perform(put("/admin/policies/" + policyId + "/entitlements/" + limitEntitlementId)
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"valueType\":\"limit\",\"value\":10}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valueType").value("limit"));

        mockMvc.perform(get("/admin/policies/" + policyId).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.entitlements.max_devices").value(10))
                .andExpect(jsonPath("$.entitlements.team_sync").value(true));

        // ─── Delete flag entitlement → snapshot drops it ──────────────────────
        mockMvc.perform(delete("/admin/policies/" + policyId + "/entitlements/" + flagEntitlementId)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/admin/policies/" + policyId).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.entitlements.team_sync").doesNotExist())
                .andExpect(jsonPath("$.entitlements.max_devices").value(10));

        // ─── Product list/get/delete ──────────────────────────────────────────
        mockMvc.perform(get("/admin/products").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '" + productId + "')]").exists());

        mockMvc.perform(get("/admin/products/" + productId).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.slug").value("acme-app"));

        // Delete the policy first (it has an entitlement with no licenses so DB allows it)
        mockMvc.perform(delete("/admin/policies/" + policyId).header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());

        // Now delete the product (no remaining policies)
        mockMvc.perform(delete("/admin/products/" + productId).header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());
    }
}
