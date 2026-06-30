package dev.hg.grantmint.server.it;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
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
import dev.hg.grantmint.server.repo.PolicyRepository;
import dev.hg.grantmint.server.repo.ProductRepository;
import dev.hg.grantmint.server.security.ApiKeyEnvironment;
import dev.hg.grantmint.server.security.ApiKeyScope;
import dev.hg.grantmint.server.security.ApiKeyService;
import dev.hg.grantmint.server.signing.SigningKeyService;
import dev.hg.grantmint.server.validation.ValidationCache;
import dev.hg.grantmint.server.validation.ValidationProperties;
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
 * End-to-end online validation against real PostgreSQL and the live Spring Security validation chain.
 * Proves the M5 contract: a freshly issued license validates ACTIVE with its live entitlements; a
 * revoked/suspended/expired license is rejected 422 with the right reason code; the cross-product
 * guard 404s a foreign key; and the cache's staleness window is real but closed instantly by an
 * evict (the hook M7's lifecycle actions will call). See docs/api/API_DOCUMENTATION.md and
 * docs/architecture/ARCHITECTURE.md (validation flow, caching).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ValidationFlowIntegrationTest extends PostgresIntegrationTest {

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
    private ValidationCache validationCache;

    @Autowired
    private ValidationRateLimiter rateLimiter;

    @Autowired
    private ValidationProperties validationProperties;

    @Autowired
    private ObjectMapper objectMapper;

    @TempDir
    Path keyDir;

    @Test
    void activeLicenseValidatesWithLiveEntitlements() throws Exception {
        Fixture fx = fixture("notes-val-active", Map.of("team_sync", true, "max_devices", 5));
        String keyId = issue(fx, null);

        validate(fx.validationKey, keyId, null)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.status").value("active"))
                .andExpect(jsonPath("$.keyId").value(keyId))
                .andExpect(jsonPath("$.entitlements.team_sync").value(true))
                .andExpect(jsonPath("$.entitlements.max_devices").value(5))
                .andExpect(jsonPath("$.expiresAt").exists())
                .andExpect(jsonPath("$.checkedAt").exists());
    }

    @Test
    void revokedLicenseFailsOnlineValidationButOnlyAfterTheCacheClears() throws Exception {
        Fixture fx = fixture("notes-val-revoked", Map.of("team_sync", true));
        String keyId = issue(fx, null);

        // Warm the cache with the ACTIVE snapshot.
        validate(fx.validationKey, keyId, null).andExpect(status().isOk());

        // Revoke in the database.
        License license = licenses.findByKeyId(keyId).orElseThrow();
        license.setStatus(LicenseStatus.REVOKED);
        license.setRevokedAt(OffsetDateTime.now(ZoneOffset.UTC));
        license.setRevocationReason("chargeback");
        licenses.save(license);

        // Until the entry expires or is evicted, the stale ACTIVE snapshot still validates — this is
        // the documented revocation-latency ceiling (bounded by the cache TTL), not a bug.
        validate(fx.validationKey, keyId, null)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));

        // The eviction hook (what M7's revoke action will call) closes the window immediately.
        validationCache.evict(keyId);
        validate(fx.validationKey, keyId, null)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("license_revoked"));
    }

    @Test
    void suspendedLicenseIsRejected() throws Exception {
        Fixture fx = fixture("notes-val-suspended", Map.of());
        String keyId = issue(fx, null);

        License license = licenses.findByKeyId(keyId).orElseThrow();
        license.setStatus(LicenseStatus.SUSPENDED);
        license.setSuspendedAt(OffsetDateTime.now(ZoneOffset.UTC));
        licenses.save(license);

        // No prior validate -> cold load sees SUSPENDED directly.
        validate(fx.validationKey, keyId, null)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("license_suspended"));
    }

    @Test
    void licenseWithAnElapsedTokenExpiryIsRejectedAsExpired() throws Exception {
        Fixture fx = fixture("notes-val-expired", Map.of("team_sync", true));
        // Issue ACTIVE but with an expiry already in the past — the token's own exp drives the rejection.
        String keyId = issue(fx, "2020-01-01T00:00:00Z");

        validate(fx.validationKey, keyId, null)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("license_expired"));
    }

    @Test
    void aForeignProductsValidationKeyCannotSeeTheLicense() throws Exception {
        Fixture owner = fixture("notes-val-owner", Map.of());
        String keyId = issue(owner, null);

        Fixture other = fixture("notes-val-intruder", Map.of());

        // The intruder's validation key resolves to a different product -> 404, never a leak.
        validate(other.validationKey, keyId, null).andExpect(status().isNotFound());
    }

    @Test
    void unknownKeyIdIsNotFound() throws Exception {
        Fixture fx = fixture("notes-val-unknown", Map.of());

        validate(fx.validationKey, "ZZZZ-ZZZZ-ZZZZ", null).andExpect(status().isNotFound());
    }

    @Test
    void missingKeyIdIsBadRequest() throws Exception {
        Fixture fx = fixture("notes-val-badreq", Map.of());

        mockMvc.perform(post("/v1/licenses/validate")
                        .header("X-Grantmint-Validation", fx.validationKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("bad_request"));
    }

    @Test
    void perKeyRateLimitReturns429WithRetryAfter() throws Exception {
        Fixture fx = fixture("notes-val-ratelimit", Map.of());
        String keyId = issue(fx, null);
        rateLimiter.reset(); // start from full buckets, isolated from other tests

        long capacity = validationProperties.getRateLimit().getPerKeyCapacity();
        for (int i = 0; i < capacity; i++) {
            validate(fx.validationKey, keyId, null).andExpect(status().isOk());
        }

        // The next call exceeds the per-key bucket -> 429 with a Retry-After hint.
        validate(fx.validationKey, keyId, null)
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.error").value("rate_limited"));
    }

    @Test
    void missingValidationCredentialIsUnauthorized() throws Exception {
        mockMvc.perform(post("/v1/licenses/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyId\":\"K7QF-9M2T-4XR8\"}"))
                .andExpect(status().isUnauthorized());
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private org.springframework.test.web.servlet.ResultActions validate(String validationKey, String keyId, String fp)
            throws Exception {
        String body = fp == null
                ? "{\"keyId\":\"" + keyId + "\"}"
                : "{\"keyId\":\"" + keyId + "\",\"fingerprint\":\"" + fp + "\"}";
        return mockMvc.perform(post("/v1/licenses/validate")
                .header("X-Grantmint-Validation", validationKey)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    private String issue(Fixture fx, String expiresAtOverride) throws Exception {
        String expiry = expiresAtOverride == null ? "" : ",\"expiresAt\":\"" + expiresAtOverride + "\"";
        MvcResult result = mockMvc.perform(post("/issuance/licenses")
                        .header("Authorization", "Bearer " + fx.issuanceKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policyId\":\"" + fx.policyId + "\",\"holder\":{\"name\":\"Jane\","
                                + "\"email\":\"jane@example.com\"}" + expiry + "}"))
                .andExpect(status().isCreated())
                .andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return body.get("keyId").asText();
    }

    private Fixture fixture(String slug, Map<String, Object> entitlements) throws IOException {
        UUID productId = newProduct(slug);
        registerSigningKey(productId, "ed25519-" + slug);
        UUID policyId = newPolicy(productId, "pro-annual", 365, 2, entitlements);
        String issuanceKey = apiKeyService
                .createProductKey(productId, ApiKeyScope.ISSUANCE, ApiKeyEnvironment.LIVE, "ci")
                .plaintext();
        String validationKey = apiKeyService
                .createProductKey(productId, ApiKeyScope.VALIDATION, ApiKeyEnvironment.LIVE, "app")
                .plaintext();
        return new Fixture(productId, policyId, issuanceKey, validationKey);
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

    private record Fixture(UUID productId, UUID policyId, String issuanceKey, String validationKey) {}
}
