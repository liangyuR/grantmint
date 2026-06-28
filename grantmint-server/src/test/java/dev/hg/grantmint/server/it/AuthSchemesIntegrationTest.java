package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.grantmint.server.domain.ApiKey;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.repo.ApiKeyRepository;
import dev.hg.grantmint.server.repo.ProductRepository;
import dev.hg.grantmint.server.security.AdminUserService;
import dev.hg.grantmint.server.security.ApiKeyEnvironment;
import dev.hg.grantmint.server.security.ApiKeyScope;
import dev.hg.grantmint.server.security.ApiKeyService;
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
 * Exercises the three M3 auth schemes end-to-end against real PostgreSQL + the live Spring Security
 * filter chains, asserting the blast-radius isolation the design promises: a validation key cannot
 * issue, an issuance key cannot administer, missing credentials are rejected, and an admin session
 * reaches the admin surface. See docs/features/ADMIN_AND_API_AUTH.md.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuthSchemesIntegrationTest extends PostgresIntegrationTest {

    private static final String ADMIN_USERNAME = "opsadmin";
    private static final String ADMIN_PASSWORD = "correct-horse-battery-staple";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ProductRepository products;

    @Autowired
    private ApiKeyRepository apiKeys;

    @Autowired
    private ApiKeyService apiKeyService;

    @Autowired
    private AdminUserService adminUsers;

    @Autowired
    private ObjectMapper objectMapper;

    private UUID newProduct(String slug) {
        Product product = new Product();
        product.setSlug(slug);
        product.setName("Acme " + slug);
        return products.save(product).getId();
    }

    private String issuanceKey(UUID productId) {
        return apiKeyService
                .createProductKey(productId, ApiKeyScope.ISSUANCE, ApiKeyEnvironment.LIVE, "ci")
                .plaintext();
    }

    private String validationKey(UUID productId) {
        return apiKeyService
                .createProductKey(productId, ApiKeyScope.VALIDATION, ApiKeyEnvironment.LIVE, "app")
                .plaintext();
    }

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

    // ── Scheme 3: validation ────────────────────────────────────────────────

    @Test
    void validationKeyValidatesOnItsOwnSurface() throws Exception {
        UUID product = newProduct("notes-val-ok");
        String key = validationKey(product);

        mockMvc.perform(get("/v1/licenses/whoami").header("X-Grantmint-Validation", key))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.productId").value(product.toString()))
                .andExpect(jsonPath("$.authorities[0]").value("SCOPE_VALIDATION"));
    }

    @Test
    void leakedValidationKeyCannotIssue() throws Exception {
        UUID product = newProduct("notes-val-noissue");
        String key = validationKey(product);

        // Real key, wrong surface: it authenticates but lacks SCOPE_ISSUE -> 403, not 401.
        mockMvc.perform(get("/issuance/whoami").header("Authorization", "Bearer " + key))
                .andExpect(status().isForbidden());
    }

    // ── Scheme 2: issuance ──────────────────────────────────────────────────

    @Test
    void issuanceKeyReachesIssuanceWithItsProductScope() throws Exception {
        UUID product = newProduct("notes-issue-ok");
        String key = issuanceKey(product);

        mockMvc.perform(get("/issuance/whoami").header("Authorization", "Bearer " + key))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.productId").value(product.toString()))
                .andExpect(jsonPath("$.authorities", org.hamcrest.Matchers.hasItem("SCOPE_ISSUE")));
    }

    @Test
    void issuanceKeyCarriesOnlyItsOwnProduct() {
        UUID productA = newProduct("acme-a");
        UUID productB = newProduct("acme-b");
        String keyA = issuanceKey(productA);

        // The auth layer scopes the key to product A; M4's issuance endpoint enforces this against
        // the target license's product. Here we prove the principal carries A and never B.
        var resolved = apiKeyService.resolveByNamespace(keyA).orElseThrow();
        assertThat(resolved.productId()).isEqualTo(productA);
        assertThat(resolved.productId()).isNotEqualTo(productB);
        assertThat(resolved.scope()).isEqualTo(ApiKeyScope.ISSUANCE);
    }

    @Test
    void leakedIssuanceKeyCannotAdminister() throws Exception {
        UUID product = newProduct("notes-issue-noadmin");
        String key = issuanceKey(product);

        // The admin chain only recognises session tokens, not API keys -> 401 (unknown credential).
        mockMvc.perform(get("/admin/whoami").header("Authorization", "Bearer " + key))
                .andExpect(status().isUnauthorized());
    }

    // ── Scheme 1: admin ─────────────────────────────────────────────────────

    @Test
    void adminSessionReachesAdminSurface() throws Exception {
        String token = adminSessionToken();

        mockMvc.perform(get("/admin/whoami").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(ADMIN_USERNAME))
                .andExpect(jsonPath("$.authorities[0]").value("ROLE_ADMIN"));
    }

    @Test
    void loginWithWrongPasswordIsUnauthorized() throws Exception {
        adminUsers.bootstrapIfEmpty(ADMIN_USERNAME, ADMIN_PASSWORD);

        mockMvc.perform(post("/admin/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + ADMIN_USERNAME + "\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("unauthorized"));
    }

    // ── Cross-cutting ───────────────────────────────────────────────────────

    @Test
    void missingCredentialIsUnauthorized() throws Exception {
        mockMvc.perform(get("/issuance/whoami")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/v1/licenses/whoami")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/admin/whoami")).andExpect(status().isUnauthorized());
    }

    @Test
    void revokedKeyIsRejected() throws Exception {
        UUID product = newProduct("notes-revoked");
        ApiKeyService.MintedKey minted =
                apiKeyService.createProductKey(product, ApiKeyScope.ISSUANCE, ApiKeyEnvironment.LIVE, "ci");
        apiKeyService.revoke(product, minted.apiKey().getId());

        mockMvc.perform(get("/issuance/whoami").header("Authorization", "Bearer " + minted.plaintext()))
                .andExpect(status().isUnauthorized());
    }

    // ── Admin API-key management (Scheme 1 protects it) ─────────────────────

    @Test
    void adminMintsIssuanceKeyAndOnlyTheHashIsStored() throws Exception {
        String token = adminSessionToken();
        UUID product = newProduct("notes-admin-mint");

        MvcResult result = mockMvc.perform(post("/admin/products/" + product + "/issuance-keys")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"stripe-webhook\",\"environment\":\"live\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.secret").exists())
                .andExpect(jsonPath("$.keyPrefix").value(org.hamcrest.Matchers.startsWith("gm_live_")))
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        String secret = body.get("secret").asText();
        UUID keyId = UUID.fromString(body.get("id").asText());

        // The plaintext authenticates...
        assertThat(apiKeyService.resolveByNamespace(secret)).isPresent();
        // ...but is never stored: only the hash persists, and it is not the plaintext.
        ApiKey stored = apiKeys.findById(keyId).orElseThrow();
        assertThat(stored.getKeyHash()).isNotEqualTo(secret);
        assertThat(secret).startsWith("gm_live_");
    }

    @Test
    void mintedKeyCannotAdministerAnotherProductsKeys() throws Exception {
        UUID productA = newProduct("acme-cross-a");
        newProduct("acme-cross-b");
        String issuanceA = issuanceKey(productA);

        // An issuance key is not an admin credential at all -> it cannot reach the admin key-management
        // surface for any product (401). Cross-product *issuance* enforcement arrives with M4.
        mockMvc.perform(post("/admin/products/" + productA + "/issuance-keys")
                        .header("Authorization", "Bearer " + issuanceA)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"x\"}"))
                .andExpect(status().isUnauthorized());
    }
}
