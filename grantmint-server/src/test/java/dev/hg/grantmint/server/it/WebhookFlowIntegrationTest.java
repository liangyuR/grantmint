package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.PolicyRepository;
import dev.hg.grantmint.server.repo.ProductRepository;
import dev.hg.grantmint.server.repo.WebhookEventRepository;
import dev.hg.grantmint.server.signing.SigningKeyService;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/**
 * End-to-end webhook ingestion against real Postgres — the M8 contract: a correctly signed Stripe
 * event drives the mapped lifecycle change; a duplicate delivery (same event id) and a second
 * issue-shaped event for the same subscription mint/change nothing twice; an unsigned, forged, or
 * replayed request is rejected 400 before anything is parsed or persisted. Deliberately not
 * {@code @Transactional}: idempotency is a database unique-index invariant and only exists across
 * committed transactions. See docs/features/WEBHOOK_INTEGRATION.md.
 */
@SpringBootTest(
        properties = {
            "grantmint.webhooks.stripe.enabled=true",
            "grantmint.webhooks.stripe.signing-secret=whsec_test_secret_1234567890", // gitleaks:allow fake test secret
            "grantmint.webhooks.stripe.tolerance-seconds=300"
        })
@AutoConfigureMockMvc
class WebhookFlowIntegrationTest extends PostgresIntegrationTest {

    private static final String SECRET = "whsec_test_secret_1234567890"; // gitleaks:allow fake test secret
    /**
     * Unique per JVM run — the webhook resolver requires exactly one policy match across products,
     * and the reused Postgres container keeps committed policies (whose signing-key seed files died
     * with their temp dirs) from previous runs. Registered into the policy-map dynamically below.
     */
    private static final String POLICY_CODE =
            "wh-pro-" + UUID.randomUUID().toString().substring(0, 8);

    @DynamicPropertySource
    static void policyMap(DynamicPropertyRegistry registry) {
        registry.add("grantmint.webhooks.stripe.policy-map.price_wh_pro", () -> POLICY_CODE);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ProductRepository products;

    @Autowired
    private PolicyRepository policies;

    @Autowired
    private LicenseRepository licenses;

    @Autowired
    private WebhookEventRepository webhookEvents;

    @Autowired
    private SigningKeyService signingKeys;

    /** Static: the signing-key seed file must outlive every test method, not just the first. */
    @TempDir
    static Path keyDir;

    @BeforeEach
    void fixture() throws IOException {
        // Create-if-absent: committed state persists across tests in this class (and container reuse).
        if (!policies.findByCode(POLICY_CODE).isEmpty()) {
            return;
        }
        Product product = new Product();
        product.setSlug("wh-acme-" + UUID.randomUUID().toString().substring(0, 8));
        product.setName("Acme Webhooks");
        UUID productId = products.save(product).getId();

        KeyPair pair = Ed25519Keys.generate(new SecureRandom());
        Path seedFile = keyDir.resolve("wh.seed");
        Files.writeString(
                seedFile,
                HexFormat.of().formatHex(Ed25519Keys.encodePrivateKey(pair.getPrivate())),
                StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(seedFile, PosixFilePermissions.fromString("rw-------"));
        signingKeys.register(
                productId, "ed25519-wh", "file:" + seedFile, Ed25519Keys.encodePublicKey(pair.getPublic()), true);

        Policy policy = new Policy();
        policy.setProduct(products.findById(productId).orElseThrow());
        policy.setCode(POLICY_CODE);
        policy.setName("Webhook Pro Annual");
        policy.setMaxSeats(2);
        policy.setDurationDays(365);
        policies.save(policy);
    }

    @Test
    void aSignedCheckoutIssuesExactlyOneLicenseAcrossRedeliveriesAndSiblingEvents() throws Exception {
        String subscription = "sub_" + UUID.randomUUID().toString().substring(0, 12);
        String checkoutEvent = checkoutEvent("evt_" + UUID.randomUUID(), subscription, "price_wh_pro");

        // First delivery mints the license from the mapped policy.
        deliverSigned(checkoutEvent)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("processed"));
        License license = onlyLicenseFor(subscription);
        assertThat(license.getStatus()).isEqualTo(LicenseStatus.ACTIVE);
        // Compare by id: getPolicy() is a lazy proxy and this test runs outside a transaction.
        UUID mappedPolicyId = policies.findByCode(POLICY_CODE).get(0).getId();
        assertThat(license.getPolicy().getId()).isEqualTo(mappedPolicyId);

        // Exact re-delivery (same event id): the unique index answers, nothing minted twice.
        deliverSigned(checkoutEvent)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("duplicate ignored"));
        assertThat(licenses.findByExternalRef(subscription)).hasSize(1);

        // A sibling issue-shaped event (new event id, same subscription): externalRef-level
        // idempotency catches what event-id idempotency cannot.
        deliverSigned(subscriptionCreatedEvent("evt_" + UUID.randomUUID(), subscription, "price_wh_pro"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ignored"));
        assertThat(licenses.findByExternalRef(subscription)).hasSize(1);
    }

    @Test
    void paymentFailureSuspendsAndRecoveryReinstates() throws Exception {
        String subscription = issueViaWebhook();

        deliverSigned(invoiceEvent("evt_" + UUID.randomUUID(), "invoice.payment_failed", subscription))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("processed"));
        assertThat(onlyLicenseFor(subscription).getStatus()).isEqualTo(LicenseStatus.SUSPENDED);

        deliverSigned(invoiceEvent("evt_" + UUID.randomUUID(), "invoice.paid", subscription))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("processed"));
        assertThat(onlyLicenseFor(subscription).getStatus()).isEqualTo(LicenseStatus.ACTIVE);

        // invoice.paid on an already-active license: recognized, converges, changes nothing.
        deliverSigned(invoiceEvent("evt_" + UUID.randomUUID(), "invoice.paid", subscription))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ignored"));
        assertThat(onlyLicenseFor(subscription).getStatus()).isEqualTo(LicenseStatus.ACTIVE);
    }

    @Test
    void subscriptionCancellationExpiresTheLicense() throws Exception {
        String subscription = issueViaWebhook();

        deliverSigned(invoiceEvent("evt_" + UUID.randomUUID(), "customer.subscription.deleted", subscription))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("processed"));
        assertThat(onlyLicenseFor(subscription).getStatus()).isEqualTo(LicenseStatus.EXPIRED);
    }

    @Test
    void forgedOrReplayedRequestsAreRejectedBeforeAnythingHappens() throws Exception {
        String subscription = "sub_" + UUID.randomUUID().toString().substring(0, 12);
        String body = checkoutEvent("evt_forged_" + UUID.randomUUID(), subscription, "price_wh_pro");
        long before = webhookEvents.count();

        // Missing signature header.
        mockMvc.perform(post("/webhooks/stripe")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());

        // Wrong signature (signed with a different secret).
        mockMvc.perform(post("/webhooks/stripe")
                        .header(
                                "Stripe-Signature",
                                sign(body, "whsec_wrong_secret", Instant.now().getEpochSecond()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());

        // Replay: correctly signed but with a timestamp far outside the tolerance window.
        mockMvc.perform(post("/webhooks/stripe")
                        .header(
                                "Stripe-Signature",
                                sign(body, SECRET, Instant.now().getEpochSecond() - 3600))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());

        assertThat(licenses.findByExternalRef(subscription)).isEmpty();
        assertThat(webhookEvents.count()).isEqualTo(before); // nothing persisted for rejected requests
    }

    @Test
    void unmappedPriceIsALoudIgnoreNotALicense() throws Exception {
        String subscription = "sub_" + UUID.randomUUID().toString().substring(0, 12);

        deliverSigned(checkoutEvent("evt_" + UUID.randomUUID(), subscription, "price_not_in_map"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ignored"));
        assertThat(licenses.findByExternalRef(subscription)).isEmpty();
    }

    @Test
    void unknownProviderIs404AndUnknownEventTypeIsIgnored200() throws Exception {
        mockMvc.perform(post("/webhooks/nonesuch")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isNotFound());

        String body =
                "{\"id\":\"evt_" + UUID.randomUUID() + "\",\"type\":\"customer.updated\",\"data\":{\"object\":{}}}";
        deliverSigned(body)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ignored"));
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private String issueViaWebhook() throws Exception {
        String subscription = "sub_" + UUID.randomUUID().toString().substring(0, 12);
        deliverSigned(checkoutEvent("evt_" + UUID.randomUUID(), subscription, "price_wh_pro"))
                .andExpect(status().isOk());
        return subscription;
    }

    private License onlyLicenseFor(String externalRef) {
        var matches = licenses.findByExternalRef(externalRef);
        assertThat(matches).hasSize(1);
        return matches.get(0);
    }

    private ResultActions deliverSigned(String body) throws Exception {
        return mockMvc.perform(post("/webhooks/stripe")
                .header("Stripe-Signature", sign(body, SECRET, Instant.now().getEpochSecond()))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    private static String checkoutEvent(String eventId, String subscription, String priceId) {
        return "{\"id\":\"" + eventId + "\",\"type\":\"checkout.session.completed\",\"data\":{\"object\":{"
                + "\"customer\":\"cus_test\",\"subscription\":\"" + subscription + "\","
                + "\"customer_details\":{\"name\":\"Jane Doe\",\"email\":\"jane@example.com\"},"
                + "\"items\":{\"data\":[{\"price\":{\"id\":\"" + priceId + "\"}}]}}}}";
    }

    private static String subscriptionCreatedEvent(String eventId, String subscription, String priceId) {
        return "{\"id\":\"" + eventId + "\",\"type\":\"customer.subscription.created\",\"data\":{\"object\":{"
                + "\"customer\":\"cus_test\",\"subscription\":\"" + subscription + "\","
                + "\"customer_details\":{\"name\":\"Jane Doe\",\"email\":\"jane@example.com\"},"
                + "\"items\":{\"data\":[{\"price\":{\"id\":\"" + priceId + "\"}}]}}}}";
    }

    private static String invoiceEvent(String eventId, String type, String subscription) {
        return "{\"id\":\"" + eventId + "\",\"type\":\"" + type + "\",\"data\":{\"object\":{" + "\"subscription\":\""
                + subscription + "\"}}}";
    }

    private static String sign(String body, String secret, long timestamp) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update((timestamp + ".").getBytes(StandardCharsets.UTF_8));
            byte[] out = mac.doFinal(body.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length * 2);
            for (byte b : out) {
                sb.append(String.format(Locale.ROOT, "%02x", b));
            }
            return "t=" + timestamp + ",v1=" + sb;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
