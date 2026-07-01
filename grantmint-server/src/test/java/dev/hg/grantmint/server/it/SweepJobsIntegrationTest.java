package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.server.activation.HeartbeatReaperJob;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.domain.MachineActivation;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.lifecycle.ExpirySweepJob;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.MachineActivationRepository;
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
import java.security.SecureRandom;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
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
 * Calls {@link ExpirySweepJob#sweep()} and {@link HeartbeatReaperJob#reap()} directly (never through
 * the scheduler) against real PostgreSQL, and asserts on repository state only.
 *
 * <p>Deliberately {@code @Transactional}: the whole test runs — and rolls back — inside one
 * transaction, joined by the jobs' own {@code @Transactional} methods (Spring's default REQUIRED
 * propagation). That means the after-commit {@link dev.hg.grantmint.server.validation.ValidationCache}
 * eviction registered by each job never fires here (there is no commit), so this class asserts row
 * state only and leaves cache-eviction behavior to {@code LifecycleFlowIntegrationTest} and
 * {@code ActivationFlowIntegrationTest}, which run non-transactionally against committed requests.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class SweepJobsIntegrationTest extends PostgresIntegrationTest {

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
    private ObjectMapper objectMapper;

    @Autowired
    private ExpirySweepJob expirySweepJob;

    @Autowired
    private HeartbeatReaperJob heartbeatReaperJob;

    @Autowired
    private Clock clock;

    @TempDir
    Path keyDir;

    @Test
    void sweepExpiresPastGraceButLeavesLicensesStillInGrace() throws Exception {
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        OffsetDateTime pastExpiry = now.minusDays(10);

        // No grace at all: 10 days past expiresAt is 10 days past the grace window too.
        Fixture noGrace = fixture("sweep-no-grace", 0, 86400);
        String noGraceKeyId = issueWithExpiry(noGrace, pastExpiry);

        // Huge grace: the same 10-days-past-expiry license is still well inside a 3650-day window.
        Fixture bigGrace = fixture("sweep-big-grace", 3650, 86400);
        String bigGraceKeyId = issueWithExpiry(bigGrace, pastExpiry);

        expirySweepJob.sweep();

        assertThat(licenses.findByKeyId(noGraceKeyId).orElseThrow().getStatus()).isEqualTo(LicenseStatus.EXPIRED);
        assertThat(licenses.findByKeyId(bigGraceKeyId).orElseThrow().getStatus())
                .isEqualTo(LicenseStatus.ACTIVE);
    }

    @Test
    void reaperExpiresStaleActivationsAndFreesTheirSeatButLeavesFreshOnesAlone() throws Exception {
        // 60s heartbeat interval -> 180s (3x) timeout.
        Fixture fx = fixture("reap-stale", 0, 60);
        String keyId = issue(fx);

        activate(fx, keyId, "fp_stale0001").andExpect(status().isCreated());
        activate(fx, keyId, "fp_fresh0001").andExpect(status().isCreated());

        License license = licenses.findByKeyId(keyId).orElseThrow();
        MachineActivation stale = activations
                .findByLicense_IdAndFingerprint(license.getId(), "fp_stale0001")
                .orElseThrow();
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        stale.setLastHeartbeatAt(now.minusSeconds(200)); // > 180s (3 * 60s) timeout
        activations.saveAndFlush(stale);

        heartbeatReaperJob.reap();

        MachineActivation reaped = activations
                .findByLicense_IdAndFingerprint(license.getId(), "fp_stale0001")
                .orElseThrow();
        assertThat(reaped.getStatus()).isEqualTo("expired");
        assertThat(reaped.getDeactivatedAt()).isNotNull();

        MachineActivation fresh = activations
                .findByLicense_IdAndFingerprint(license.getId(), "fp_fresh0001")
                .orElseThrow();
        assertThat(fresh.getStatus()).isEqualTo("active");

        assertThat(activations.countActiveByKeyId(keyId)).isEqualTo(1);
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private org.springframework.test.web.servlet.ResultActions activate(Fixture fx, String keyId, String fingerprint)
            throws Exception {
        return mockMvc.perform(post("/v1/licenses/activate")
                .header("X-Grantmint-Validation", fx.validationKey)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"keyId\":\"" + keyId + "\",\"fingerprint\":\"" + fingerprint + "\"}"));
    }

    private String issue(Fixture fx) throws Exception {
        return issueWithExpiry(fx, null);
    }

    private String issueWithExpiry(Fixture fx, OffsetDateTime expiresAt) throws Exception {
        String body = expiresAt == null
                ? "{\"policyId\":\"" + fx.policyId + "\",\"holder\":{\"name\":\"Jane\","
                        + "\"email\":\"jane@example.com\"}}"
                : "{\"policyId\":\"" + fx.policyId + "\",\"holder\":{\"name\":\"Jane\","
                        + "\"email\":\"jane@example.com\"},\"expiresAt\":\"" + expiresAt + "\"}";
        MvcResult result = mockMvc.perform(post("/issuance/licenses")
                        .header("Authorization", "Bearer " + fx.issuanceKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andReturn();
        JsonNode responseBody = objectMapper.readTree(result.getResponse().getContentAsString());
        return responseBody.get("keyId").asText();
    }

    private Fixture fixture(String slug, int gracePeriodDays, int heartbeatIntervalSeconds) throws IOException {
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
        policy.setGracePeriodDays(gracePeriodDays);
        policy.setHeartbeatIntervalSeconds(heartbeatIntervalSeconds);
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
