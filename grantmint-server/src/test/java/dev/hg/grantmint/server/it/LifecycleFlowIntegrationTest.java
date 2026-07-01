package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.grantmint.core.crypto.Ed25519Keys;
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
import dev.hg.grantmint.server.validation.ValidationRateLimiter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * End-to-end lifecycle actions against real Postgres, the live issuance chain, and — crucially — a
 * <b>committing</b> transaction per request: this class is deliberately not {@code @Transactional},
 * so the after-commit cache eviction actually fires and the test can prove the M5→M7 promise that a
 * suspend/revoke is visible to online validation <em>immediately</em>, not a TTL later. Also pins
 * the 409 {@code invalid_state_transition} surface (revocation terminal, reinstate only from
 * suspended) and the per-method SCOPE_REVOKE gate. See docs/features/LICENSE_LIFECYCLE.md.
 */
@SpringBootTest
@AutoConfigureMockMvc
class LifecycleFlowIntegrationTest extends PostgresIntegrationTest {

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
    private ValidationRateLimiter rateLimiter;

    @Autowired
    private ObjectMapper objectMapper;

    @TempDir
    Path keyDir;

    @BeforeEach
    void freshBuckets() {
        rateLimiter.reset();
    }

    @Test
    void suspendIsVisibleToOnlineValidationImmediatelyAndReinstateRestores() throws Exception {
        Fixture fx = fixture("life-suspend");
        String keyId = issue(fx);

        // Warm the validation cache with the healthy snapshot.
        validate(fx, keyId).andExpect(status().isOk());

        suspend(fx, keyId, "payment_failed")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("suspended"))
                .andExpect(jsonPath("$.suspendedAt").exists())
                .andExpect(jsonPath("$.reason").value("payment_failed"));

        // No TTL wait, no manual evict: the commit hook must have dropped the cached ACTIVE snapshot.
        validate(fx, keyId)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("license_suspended"));

        reinstate(fx, keyId)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("active"))
                .andExpect(jsonPath("$.suspendedAt").doesNotExist());

        validate(fx, keyId)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
    }

    @Test
    void revokeIsTerminalAndImmediatelyFatalOnline() throws Exception {
        Fixture fx = fixture("life-revoke");
        String keyId = issue(fx);
        validate(fx, keyId).andExpect(status().isOk());

        revoke(fx, keyId, "chargeback")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("revoked"))
                .andExpect(jsonPath("$.revokedAt").exists())
                .andExpect(jsonPath("$.reason").value("chargeback"));

        validate(fx, keyId)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("license_revoked"));

        // Terminal: neither reinstate nor a second revoke may move it.
        reinstate(fx, keyId)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("invalid_state_transition"));
        revoke(fx, keyId, "again").andExpect(status().isConflict());
        assertThat(licenses.findByKeyId(keyId).orElseThrow().getStatus()).isEqualTo(LicenseStatus.REVOKED);
    }

    @Test
    void reinstatingAnActiveLicenseIsAnIllegalTransition() throws Exception {
        Fixture fx = fixture("life-badmove");
        String keyId = issue(fx);

        reinstate(fx, keyId)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("invalid_state_transition"));
    }

    @Test
    void aForeignProductsIssuanceKeyCannotTouchTheLicense() throws Exception {
        Fixture owner = fixture("life-owner");
        String keyId = issue(owner);
        Fixture intruder = fixture("life-intruder");

        suspend(intruder, keyId, null).andExpect(status().isNotFound());
        revoke(intruder, keyId, null).andExpect(status().isNotFound());
        assertThat(licenses.findByKeyId(keyId).orElseThrow().getStatus()).isEqualTo(LicenseStatus.ACTIVE);
    }

    @Test
    void aValidationKeyCannotDriveLifecycleActions() throws Exception {
        Fixture fx = fixture("life-lowpriv");
        String keyId = issue(fx);

        // The validation key authenticates on the wrong chain entirely — the issuance chain rejects it.
        mockMvc.perform(post("/issuance/licenses/" + keyId + "/suspend")
                        .header("X-Grantmint-Validation", fx.validationKey)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
        assertThat(licenses.findByKeyId(keyId).orElseThrow().getStatus()).isEqualTo(LicenseStatus.ACTIVE);
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private ResultActions suspend(Fixture fx, String keyId, String reason) throws Exception {
        var request = post("/issuance/licenses/" + keyId + "/suspend")
                .header("Authorization", "Bearer " + fx.issuanceKey)
                .contentType(MediaType.APPLICATION_JSON);
        if (reason != null) {
            request = request.content("{\"reason\":\"" + reason + "\"}");
        }
        return mockMvc.perform(request);
    }

    private ResultActions reinstate(Fixture fx, String keyId) throws Exception {
        return mockMvc.perform(
                post("/issuance/licenses/" + keyId + "/reinstate").header("Authorization", "Bearer " + fx.issuanceKey));
    }

    private ResultActions revoke(Fixture fx, String keyId, String reason) throws Exception {
        var request = delete("/issuance/licenses/" + keyId).header("Authorization", "Bearer " + fx.issuanceKey);
        if (reason != null) {
            request = request.contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\"" + reason + "\"}");
        }
        return mockMvc.perform(request);
    }

    private ResultActions validate(Fixture fx, String keyId) throws Exception {
        return mockMvc.perform(post("/v1/licenses/validate")
                .header("X-Grantmint-Validation", fx.validationKey)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"keyId\":\"" + keyId + "\"}"));
    }

    private String issue(Fixture fx) throws Exception {
        MvcResult result = mockMvc.perform(post("/issuance/licenses")
                        .header("Authorization", "Bearer " + fx.issuanceKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policyId\":\"" + fx.policyId + "\",\"holder\":{\"name\":\"Jane\","
                                + "\"email\":\"jane@example.com\"}}"))
                .andExpect(status().isCreated())
                .andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return body.get("keyId").asText();
    }

    private Fixture fixture(String prefix) throws IOException {
        String slug = prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
        Product product = new Product();
        product.setSlug(slug);
        product.setName("Acme " + slug);
        UUID productId = products.save(product).getId();

        KeyPair pair = Ed25519Keys.generate(new SecureRandom());
        byte[] seed = Ed25519Keys.encodePrivateKey(pair.getPrivate());
        byte[] publicKey = Ed25519Keys.encodePublicKey(pair.getPublic());
        Path seedFile = keyDir.resolve(slug + ".seed");
        Files.writeString(seedFile, HexFormat.of().formatHex(seed), StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(seedFile, PosixFilePermissions.fromString("rw-------"));
        signingKeys.register(productId, "ed25519-" + slug, "file:" + seedFile, publicKey, true);

        Policy policy = new Policy();
        policy.setProduct(products.findById(productId).orElseThrow());
        policy.setCode("pro-annual");
        policy.setName("Pro Annual");
        policy.setMaxSeats(2);
        policy.setDurationDays(365);
        UUID policyId = policies.save(policy).getId();

        String issuanceKey = apiKeyService
                .createProductKey(productId, ApiKeyScope.ISSUANCE, ApiKeyEnvironment.LIVE, "ci")
                .plaintext();
        String validationKey = apiKeyService
                .createProductKey(productId, ApiKeyScope.VALIDATION, ApiKeyEnvironment.LIVE, "app")
                .plaintext();
        return new Fixture(productId, policyId, issuanceKey, validationKey);
    }

    private record Fixture(UUID productId, UUID policyId, String issuanceKey, String validationKey) {}
}
