package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.time.Clock;
import dev.hg.grantmint.core.token.LicenseVerifier;
import dev.hg.grantmint.core.token.VerificationResult;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.PolicyRepository;
import dev.hg.grantmint.server.repo.ProductRepository;
import dev.hg.grantmint.server.security.ApiKeyEnvironment;
import dev.hg.grantmint.server.security.ApiKeyScope;
import dev.hg.grantmint.server.security.ApiKeyService;
import dev.hg.grantmint.server.signing.SigningKeyService;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.PublicKey;
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
 * End-to-end issuance against real PostgreSQL and the live Spring Security issuance chain: minting a
 * license persists it ACTIVE and yields a token that verifies offline against the registered public
 * key, and an issuance key scoped to one product cannot mint a license from another product's policy
 * (403). See docs/architecture/ARCHITECTURE.md (the issuance flow) and ADMIN_AND_API_AUTH.md.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class IssuanceFlowIntegrationTest extends PostgresIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ProductRepository products;

    @Autowired
    private PolicyRepository policies;

    @Autowired
    private LicenseRepository licenses;

    @Autowired
    private SigningKeyService signingKeys;

    @Autowired
    private ApiKeyService apiKeyService;

    @Autowired
    private ObjectMapper objectMapper;

    @TempDir
    Path keyDir;

    @Test
    void issuesLicenseThatPersistsActiveAndVerifiesOffline() throws Exception {
        UUID product = newProduct("notes-issue-e2e");
        PublicKey publicKey = registerSigningKey(product, "ed25519-issue-e2e");
        UUID policy = newPolicy(product, "pro-annual", 365, 2, Map.of("team_sync", true, "max_devices", 5));
        String key = issuanceKey(product);

        MvcResult result = mockMvc.perform(post("/issuance/licenses")
                        .header("Authorization", "Bearer " + key)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policyId\":\"" + policy + "\",\"holder\":{\"name\":\"Jane Doe\","
                                + "\"email\":\"jane@example.com\"}}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.keyId").exists())
                .andExpect(jsonPath("$.status").value("active"))
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.expiresAt").exists())
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        String keyId = body.get("keyId").asText();
        String token = body.get("token").asText();

        // Persisted truth: the license resolves ACTIVE with the policy's entitlement snapshot.
        License license = licenses.findByKeyId(keyId).orElseThrow();
        assertThat(license.getStatus()).isEqualTo(LicenseStatus.ACTIVE);
        assertThat(license.getEntitlements()).containsEntry("team_sync", true);
        assertThat(license.getMaxSeats()).isEqualTo(2);
        assertThat(license.getHolderEmail()).isEqualTo("jane@example.com");

        // Offline truth: the token verifies against the registered public key with no server.
        VerificationResult verified =
                LicenseVerifier.verifyAt(token, Ed25519Keys.decodePublicKey(encode(publicKey)), Clock.system());
        assertThat(verified.isValid()).isTrue();
        assertThat(verified.payload().kid()).isEqualTo(keyId);
        assertThat(verified.payload().prd()).isEqualTo("notes-issue-e2e");
        assertThat(verified.payload().pol()).isEqualTo("pro-annual");
        assertThat(verified.payload().lid()).isEqualTo(license.getId().toString());
    }

    @Test
    void issuanceKeyCannotMintAnotherProductsPolicy() throws Exception {
        UUID productA = newProduct("acme-a-cross");
        UUID productB = newProduct("acme-b-cross");
        registerSigningKey(productA, "ed25519-a-cross");
        registerSigningKey(productB, "ed25519-b-cross");
        UUID policyB = newPolicy(productB, "pro", 30, 1, Map.of());
        String keyA = issuanceKey(productA);

        // Product A's issuance key, minting from product B's policy -> denied (403), nothing persisted.
        mockMvc.perform(post("/issuance/licenses")
                        .header("Authorization", "Bearer " + keyA)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policyId\":\"" + policyB + "\",\"holder\":{\"name\":\"Eve\","
                                + "\"email\":\"eve@example.com\"}}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("forbidden"));

        assertThat(licenses.findByHolderEmailIgnoreCase("eve@example.com")).isEmpty();
    }

    private UUID newProduct(String slug) {
        Product product = new Product();
        product.setSlug(slug);
        product.setName("Acme " + slug);
        return products.save(product).getId();
    }

    private PublicKey registerSigningKey(UUID productId, String keyId) throws IOException {
        KeyPair pair = Ed25519Keys.generate(new SecureRandom());
        byte[] seed = Ed25519Keys.encodePrivateKey(pair.getPrivate());
        byte[] publicKey = Ed25519Keys.encodePublicKey(pair.getPublic());
        Path seedFile = keyDir.resolve(keyId + ".seed");
        Files.writeString(seedFile, HexFormat.of().formatHex(seed), StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(seedFile, PosixFilePermissions.fromString("rw-------"));
        signingKeys.register(productId, keyId, "file:" + seedFile, publicKey, true);
        return pair.getPublic();
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

    private String issuanceKey(UUID productId) {
        return apiKeyService
                .createProductKey(productId, ApiKeyScope.ISSUANCE, ApiKeyEnvironment.LIVE, "ci")
                .plaintext();
    }

    private static byte[] encode(PublicKey publicKey) {
        return Ed25519Keys.encodePublicKey(publicKey);
    }
}
