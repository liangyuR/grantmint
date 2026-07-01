package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.MachineActivationRepository;
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
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Map;
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
import org.springframework.transaction.annotation.Transactional;

/**
 * End-to-end node-locked activation against real PostgreSQL and the live Scheme-3 security chain —
 * the M6 contract. Walks the documented 2-seat worked example (activate, block at the limit,
 * idempotent re-activate, deactivate frees, re-fit), proves the CREATED→ACTIVE first-contact
 * transition, and pins the failure surface (409 seat_limit_exceeded, 404 activation_not_found, 422
 * for unusable licenses, 404 cross-product). See docs/features/ACTIVATION_AND_SEATS.md.
 *
 * <p>Serialized seat-limit enforcement under real concurrent contention is covered separately by
 * {@code SeatConcurrencyIntegrationTest}, which needs committing transactions.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ActivationFlowIntegrationTest extends PostgresIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

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
    private ApiKeyService apiKeyService;

    @Autowired
    private ValidationRateLimiter rateLimiter;

    @Autowired
    private ObjectMapper objectMapper;

    @TempDir
    Path keyDir;

    @BeforeEach
    void freshBuckets() {
        // Every request here shares the MockMvc client IP; start each test from full buckets so the
        // per-IP limiter never bleeds across tests.
        rateLimiter.reset();
    }

    @Test
    void theTwoSeatWorkedExample() throws Exception {
        Fixture fx = fixture("notes-act-worked");
        String keyId = issue(fx);

        // 1 & 2 — A and B activate within the limit.
        activate(fx, keyId, "fp_aaaa1111")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.seatsUsed").value(1))
                .andExpect(jsonPath("$.seatsTotal").value(2))
                .andExpect(jsonPath("$.reactivated").value(false))
                .andExpect(jsonPath("$.status").value("active"))
                .andExpect(jsonPath("$.activationId").exists())
                .andExpect(jsonPath("$.nextHeartbeatDueBy").exists());
        activate(fx, keyId, "fp_bbbb2222")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.seatsUsed").value(2));

        // 3 — C is blocked at the seat limit.
        activate(fx, keyId, "fp_cccc3333")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("seat_limit_exceeded"));

        // 4 — A re-activates: idempotent, still 2/2, no new seat.
        activate(fx, keyId, "fp_aaaa1111")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reactivated").value(true))
                .andExpect(jsonPath("$.seatsUsed").value(2));

        // 5 — A deactivates, freeing a seat.
        deactivate(fx, keyId, "fp_aaaa1111")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deactivated").value(true))
                .andExpect(jsonPath("$.seatsUsed").value(1));

        // 6 — C now fits; the deactivated row's fingerprint stays unique per license.
        activate(fx, keyId, "fp_cccc3333")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.seatsUsed").value(2));

        License license = licenses.findByKeyId(keyId).orElseThrow();
        assertThat(activations.countActiveByKeyId(keyId)).isEqualTo(2);
        assertThat(activations.findByLicense_Id(license.getId())).hasSize(3); // A(deactivated), B, C
    }

    @Test
    void firstActivationTransitionsCreatedToActive() throws Exception {
        Fixture fx = fixture("notes-act-lifecycle");
        String keyId = issue(fx);

        License before = licenses.findByKeyId(keyId).orElseThrow();
        before.setStatus(LicenseStatus.CREATED);
        before.setActivatedAt(null);
        licenses.saveAndFlush(before);

        activate(fx, keyId, "fp_first0001").andExpect(status().isCreated());

        License after = licenses.findByKeyId(keyId).orElseThrow();
        assertThat(after.getStatus()).isEqualTo(LicenseStatus.ACTIVE);
        assertThat(after.getActivatedAt()).isNotNull();
    }

    @Test
    void reactivatingADeactivatedFingerprintReusesItsRowAndCountsAsASeat() throws Exception {
        Fixture fx = fixture("notes-act-flip");
        String keyId = issue(fx);

        activate(fx, keyId, "fp_flip00001").andExpect(status().isCreated());
        deactivate(fx, keyId, "fp_flip00001").andExpect(status().isOk());

        // Comes back as a fresh 201 claim (subject to the seat check), on the same unique row.
        activate(fx, keyId, "fp_flip00001")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.seatsUsed").value(1));
        License license = licenses.findByKeyId(keyId).orElseThrow();
        assertThat(activations.findByLicense_Id(license.getId())).hasSize(1);
    }

    @Test
    void activatingARevokedLicenseIsRejected422() throws Exception {
        Fixture fx = fixture("notes-act-revoked");
        String keyId = issue(fx);

        License license = licenses.findByKeyId(keyId).orElseThrow();
        license.setStatus(LicenseStatus.REVOKED);
        license.setRevokedAt(OffsetDateTime.now(ZoneOffset.UTC));
        license.setRevocationReason("chargeback");
        licenses.saveAndFlush(license);

        activate(fx, keyId, "fp_revk00001")
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("license_revoked"));
    }

    @Test
    void deactivatingAnUnknownFingerprintIs404AndNeverCorruptsTheCount() throws Exception {
        Fixture fx = fixture("notes-act-deact404");
        String keyId = issue(fx);
        activate(fx, keyId, "fp_only00001").andExpect(status().isCreated());

        deactivate(fx, keyId, "fp_ghost0001")
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("activation_not_found"));

        // Deactivating twice: the second call finds no active seat — 404, count untouched at 0.
        deactivate(fx, keyId, "fp_only00001").andExpect(status().isOk());
        deactivate(fx, keyId, "fp_only00001").andExpect(status().isNotFound());
        assertThat(activations.countActiveByKeyId(keyId)).isZero();
    }

    @Test
    void heartbeatTouchesTheSeatAndAdvertisesTheNextDeadline() throws Exception {
        Fixture fx = fixture("notes-act-heartbeat");
        String keyId = issue(fx);
        activate(fx, keyId, "fp_beat00001").andExpect(status().isCreated());

        License license = licenses.findByKeyId(keyId).orElseThrow();
        OffsetDateTime before = activations
                .findByLicense_IdAndFingerprint(license.getId(), "fp_beat00001")
                .orElseThrow()
                .getLastHeartbeatAt();

        heartbeat(fx, keyId, "fp_beat00001")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.licenseStatus").value("active"))
                .andExpect(jsonPath("$.machineStatus").value("active"))
                .andExpect(jsonPath("$.lastHeartbeatAt").exists())
                .andExpect(jsonPath("$.nextHeartbeatDueBy").exists());

        OffsetDateTime after = activations
                .findByLicense_IdAndFingerprint(license.getId(), "fp_beat00001")
                .orElseThrow()
                .getLastHeartbeatAt();
        assertThat(after).isAfterOrEqualTo(before);
    }

    @Test
    void heartbeatIsHowADeviceLearnsAboutRevocation() throws Exception {
        Fixture fx = fixture("notes-act-beat-revoked");
        String keyId = issue(fx);
        activate(fx, keyId, "fp_beat00002").andExpect(status().isCreated());

        License license = licenses.findByKeyId(keyId).orElseThrow();
        license.setStatus(LicenseStatus.REVOKED);
        license.setRevokedAt(OffsetDateTime.now(ZoneOffset.UTC));
        licenses.saveAndFlush(license);

        heartbeat(fx, keyId, "fp_beat00002")
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("license_revoked"));
    }

    @Test
    void heartbeatOnAReleasedSeatTellsTheClientToReactivate() throws Exception {
        Fixture fx = fixture("notes-act-beat-gone");
        String keyId = issue(fx);
        activate(fx, keyId, "fp_beat00003").andExpect(status().isCreated());
        deactivate(fx, keyId, "fp_beat00003").andExpect(status().isOk());

        heartbeat(fx, keyId, "fp_beat00003")
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("activation_not_found"));
    }

    @Test
    void aForeignProductsValidationKeyCannotActivateTheLicense() throws Exception {
        Fixture owner = fixture("notes-act-owner");
        String keyId = issue(owner);
        Fixture intruder = fixture("notes-act-intruder");

        activate(intruder, keyId, "fp_steal0001").andExpect(status().isNotFound());
        deactivate(intruder, keyId, "fp_steal0001").andExpect(status().isNotFound());
        heartbeat(intruder, keyId, "fp_steal0001").andExpect(status().isNotFound());
        assertThat(activations.countActiveByKeyId(keyId)).isZero();
    }

    @Test
    void missingFingerprintOrKeyIdIsBadRequest() throws Exception {
        Fixture fx = fixture("notes-act-badreq");
        String keyId = issue(fx);

        mockMvc.perform(post("/v1/licenses/activate")
                        .header("X-Grantmint-Validation", fx.validationKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyId\":\"" + keyId + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("bad_request"));

        mockMvc.perform(post("/v1/licenses/activate")
                        .header("X-Grantmint-Validation", fx.validationKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fingerprint\":\"fp_nokey0001\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void activationEndpointsRequireTheValidationCredential() throws Exception {
        for (String path : new String[] {"activate", "deactivate", "heartbeat"}) {
            mockMvc.perform(post("/v1/licenses/" + path)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"keyId\":\"K7QF-9M2T-4XR8\",\"fingerprint\":\"fp_anon00001\"}"))
                    .andExpect(status().isUnauthorized());
        }
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private ResultActions activate(Fixture fx, String keyId, String fingerprint) throws Exception {
        return mockMvc.perform(post("/v1/licenses/activate")
                .header("X-Grantmint-Validation", fx.validationKey)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"keyId\":\"" + keyId + "\",\"fingerprint\":\"" + fingerprint + "\"}"));
    }

    private ResultActions deactivate(Fixture fx, String keyId, String fingerprint) throws Exception {
        return mockMvc.perform(post("/v1/licenses/deactivate")
                .header("X-Grantmint-Validation", fx.validationKey)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"keyId\":\"" + keyId + "\",\"fingerprint\":\"" + fingerprint + "\"}"));
    }

    private ResultActions heartbeat(Fixture fx, String keyId, String fingerprint) throws Exception {
        return mockMvc.perform(post("/v1/licenses/heartbeat")
                .header("X-Grantmint-Validation", fx.validationKey)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"keyId\":\"" + keyId + "\",\"fingerprint\":\"" + fingerprint + "\"}"));
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

    private Fixture fixture(String slug) throws IOException {
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
        policy.setEntitlements(new java.util.HashMap<>(Map.of("team_sync", true)));
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
