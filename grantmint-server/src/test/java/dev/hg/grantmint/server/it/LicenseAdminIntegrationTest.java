package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.server.activation.ActivationCommand;
import dev.hg.grantmint.server.activation.ActivationResult;
import dev.hg.grantmint.server.activation.ActivationService;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.MachineActivationRepository;
import dev.hg.grantmint.server.repo.PolicyRepository;
import dev.hg.grantmint.server.repo.ProductRepository;
import dev.hg.grantmint.server.security.AdminUserService;
import dev.hg.grantmint.server.signing.SigningKeyService;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

/**
 * Integration tests for the admin license-management surface ({@code /admin/licenses/**}), reachable
 * only via the admin session cookie/bearer — the dashboard's route since the per-product
 * {@code /issuance/**} endpoints are unreachable for a browser. Exercises list filtering + pagination
 * envelope, detail (including the signed token and activations), admin issuance, the
 * suspend/revoke lifecycle, force-deactivating a seat, and the 404 contract for an unknown key id.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class LicenseAdminIntegrationTest extends PostgresIntegrationTest {

    private static final String ADMIN_USERNAME = "licenseadmin";
    private static final String ADMIN_PASSWORD = "battery-staple-correct-horse";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AdminUserService adminUsers;

    @Autowired
    private ProductRepository products;

    @Autowired
    private PolicyRepository policies;

    @Autowired
    private LicenseRepository licenses;

    @Autowired
    private MachineActivationRepository activations;

    @Autowired
    private SigningKeyService signingKeys;

    @Autowired
    private ActivationService activationService;

    @Autowired
    private ObjectMapper objectMapper;

    @TempDir
    Path keyDir;

    @Test
    void deletingProductWithIssuedLicenseReturnsConflictAndPreservesBoth() throws Exception {
        String token = adminSessionToken();
        Fixture fx = fixture("licadmin-product-delete");
        String keyId = issue(token, fx, "Demo Customer", "demo@customer.example");

        mockMvc.perform(delete("/admin/products/" + fx.productId()).header("Authorization", "Bearer " + token))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("product_has_licenses"));

        mockMvc.perform(get("/admin/products/" + fx.productId()).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(fx.productId().toString()));
        mockMvc.perform(get("/admin/licenses/" + keyId).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.productId").value(fx.productId().toString()));
    }

    @Test
    void listFiltersByStatusAndReturnsThePaginationEnvelope() throws Exception {
        String token = adminSessionToken();
        Fixture fx = fixture("licadmin-list");
        String keyId = issue(token, fx, "Dana Okoro", "dana@customer.example");

        mockMvc.perform(get("/admin/licenses")
                        .header("Authorization", "Bearer " + token)
                        .param("status", "active")
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(10))
                .andExpect(jsonPath("$.total").isNumber())
                .andExpect(jsonPath("$.items[?(@.keyId == '" + keyId + "')]").exists())
                .andExpect(jsonPath("$.items[?(@.keyId == '" + keyId + "')].signedToken")
                        .doesNotExist());
    }

    @Test
    void detailIncludesTheSignedTokenAndActivations() throws Exception {
        String token = adminSessionToken();
        Fixture fx = fixture("licadmin-detail");
        String keyId = issue(token, fx, "Jane Doe", "jane@customer.example");

        mockMvc.perform(get("/admin/licenses/" + keyId).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyId").value(keyId))
                .andExpect(jsonPath("$.policyId").value(fx.policyId().toString()))
                .andExpect(jsonPath("$.signedToken").exists())
                .andExpect(jsonPath("$.activations").isArray())
                .andExpect(jsonPath("$.activations.length()").value(0));
    }

    @Test
    void adminIssueReturns201WithAKeyId() throws Exception {
        String token = adminSessionToken();
        Fixture fx = fixture("licadmin-issue");

        MvcResult result = mockMvc.perform(post("/admin/licenses")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"productId\":\"" + fx.productId() + "\",\"policyId\":\"" + fx.policyId()
                                + "\",\"holder\":{\"name\":\"Ada\",\"email\":\"ada@customer.example\"}}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.keyId").exists())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.status").value("active"))
                .andReturn();

        String keyId = objectMapper
                .readTree(result.getResponse().getContentAsString())
                .get("keyId")
                .asText();
        assertThat(licenses.findByKeyId(keyId)).isPresent();
    }

    @Test
    void suspendTransitionsToSuspendedInTheDatabase() throws Exception {
        String token = adminSessionToken();
        Fixture fx = fixture("licadmin-suspend");
        String keyId = issue(token, fx, "Kim Lee", "kim@customer.example");

        mockMvc.perform(post("/admin/licenses/" + keyId + "/suspend")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"payment_failed\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("suspended"));

        License license = licenses.findByKeyId(keyId).orElseThrow();
        assertThat(license.getStatus()).isEqualTo(LicenseStatus.SUSPENDED);
    }

    @Test
    void revokeIsTerminal() throws Exception {
        String token = adminSessionToken();
        Fixture fx = fixture("licadmin-revoke");
        String keyId = issue(token, fx, "Sam Rivera", "sam@customer.example");

        mockMvc.perform(delete("/admin/licenses/" + keyId)
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"chargeback\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("revoked"));

        License license = licenses.findByKeyId(keyId).orElseThrow();
        assertThat(license.getStatus()).isEqualTo(LicenseStatus.REVOKED);
    }

    @Test
    void forceDeactivateFreesTheSeat() throws Exception {
        String token = adminSessionToken();
        Fixture fx = fixture("licadmin-deactivate");
        String keyId = issue(token, fx, "Lee Park", "lee@customer.example");

        ActivationResult activation = activationService.activate(
                new ActivationCommand(keyId, fx.productId(), "fp-force-deactivate", null, null, null, "test", null));
        assertThat(activations.countActiveByKeyId(keyId)).isEqualTo(1);

        mockMvc.perform(delete("/admin/licenses/" + keyId + "/activations/" + activation.activationId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());

        assertThat(activations.countActiveByKeyId(keyId)).isZero();
    }

    @Test
    void unknownKeyIdIsNotFound() throws Exception {
        String token = adminSessionToken();

        mockMvc.perform(get("/admin/licenses/ZZZZ-ZZZZ-ZZZZ").header("Authorization", "Bearer " + token))
                .andExpect(status().isNotFound());
    }

    // ── helpers ─────────────────────────────────────────────────────────────

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

    private String issue(String adminToken, Fixture fx, String holderName, String holderEmail) throws Exception {
        MvcResult result = mockMvc.perform(post("/admin/licenses")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"productId\":\"" + fx.productId() + "\",\"policyId\":\"" + fx.policyId()
                                + "\",\"holder\":{\"name\":\"" + holderName + "\",\"email\":\"" + holderEmail + "\"}}"))
                .andExpect(status().isCreated())
                .andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return body.get("keyId").asText();
    }

    private Fixture fixture(String slug) throws IOException {
        UUID productId = newProduct(slug);
        registerSigningKey(productId, "ed25519-" + slug);
        UUID policyId = newPolicy(productId, "pro-annual", 365, 2, Map.of("team_sync", true));
        return new Fixture(productId, policyId);
    }

    private UUID newProduct(String slug) {
        Product product = new Product();
        product.setSlug(slug);
        product.setName("Acme " + slug);
        return products.save(product).getId();
    }

    private void registerSigningKey(UUID productId, String keyId) throws IOException {
        KeyPair pair = Ed25519Keys.generate(new SecureRandom());
        byte[] seed = Ed25519Keys.encodePrivateKey(pair.getPrivate());
        byte[] publicKey = Ed25519Keys.encodePublicKey(pair.getPublic());
        Path seedFile = keyDir.resolve(keyId + ".seed");
        Files.writeString(seedFile, HexFormat.of().formatHex(seed), StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(seedFile, PosixFilePermissions.fromString("rw-------"));
        signingKeys.register(productId, keyId, "file:" + seedFile, publicKey, true);
    }

    private UUID newPolicy(UUID productId, String code, Integer durationDays, int seats, Map<String, Object> ent) {
        Policy policy = new Policy();
        policy.setProduct(products.findById(productId).orElseThrow());
        policy.setCode(code);
        policy.setName(code);
        policy.setMaxSeats(seats);
        policy.setDurationDays(durationDays);
        policy.setEntitlements(new java.util.HashMap<>(ent));
        return policies.save(policy).getId();
    }

    private record Fixture(UUID productId, UUID policyId) {}
}
