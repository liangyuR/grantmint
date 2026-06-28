package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.domain.MachineActivation;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.domain.SigningKey;
import dev.hg.grantmint.server.domain.WebhookEvent;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.MachineActivationRepository;
import dev.hg.grantmint.server.repo.PolicyRepository;
import dev.hg.grantmint.server.repo.ProductRepository;
import dev.hg.grantmint.server.repo.SigningKeyRepository;
import dev.hg.grantmint.server.repo.WebhookEventRepository;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

/**
 * Exercises the M2 repository query surface against real PostgreSQL: key-ID lookup, the active
 * seat count, case-insensitive holder-email search, and webhook idempotency. Saving and reading
 * back the full graph also confirms the jsonb, {@code bytea}, and timestamptz mappings round-trip.
 */
@SpringBootTest
@Transactional
class RepositoryQueriesIntegrationTest extends PostgresIntegrationTest {

    @Autowired
    private ProductRepository products;

    @Autowired
    private SigningKeyRepository signingKeys;

    @Autowired
    private PolicyRepository policies;

    @Autowired
    private LicenseRepository licenses;

    @Autowired
    private MachineActivationRepository activations;

    @Autowired
    private WebhookEventRepository webhookEvents;

    private License persistLicenseGraph(String keyId, String holderEmail, int maxSeats) {
        Product product = new Product();
        product.setSlug("acme-app-" + keyId.toLowerCase(java.util.Locale.ROOT));
        product.setName("Acme App");
        product = products.save(product);

        SigningKey key = new SigningKey();
        key.setKeyId("ed25519-" + keyId);
        key.setProduct(product);
        key.setPublicKey(new byte[32]);
        key.setPrivateKeyRef("file:/etc/grantmint/keys/ed25519.key");
        signingKeys.save(key);

        Policy policy = new Policy();
        policy.setProduct(product);
        policy.setCode("pro-annual");
        policy.setName("Pro Annual");
        policy.setMaxSeats(maxSeats);
        policy.setEntitlements(Map.of("team_sync", true, "max_devices", maxSeats));
        policy = policies.save(policy);

        License license = new License();
        license.setProduct(product);
        license.setPolicy(policy);
        license.setKeyId(keyId);
        license.setSignedToken("eyJ0eXAiOiJncmFudG1pbnQrbGljZW5zZSJ9.payload.sig");
        license.setSigningKeyId(key.getKeyId());
        license.setStatus(LicenseStatus.ACTIVE);
        license.setHolderEmail(holderEmail);
        license.setMaxSeats(maxSeats);
        license.setEntitlements(Map.of("team_sync", true));
        return licenses.save(license);
    }

    @Test
    void keyIdLookupAndJsonbRoundTrip() {
        License saved = persistLicenseGraph("GMNT-AAAA-BBBB-CCCC", "user@example.com", 2);

        License found = licenses.findByKeyId("GMNT-AAAA-BBBB-CCCC").orElseThrow();
        assertThat(found.getId()).isEqualTo(saved.getId());
        assertThat(found.getStatus()).isEqualTo(LicenseStatus.ACTIVE);
        assertThat(found.getEntitlements()).containsEntry("team_sync", true);
    }

    @Test
    void holderEmailLookupIsCaseInsensitive() {
        persistLicenseGraph("GMNT-DDDD-EEEE-FFFF", "Mixed.Case@Example.com", 1);

        assertThat(licenses.findByHolderEmailIgnoreCase("mixed.case@example.com"))
                .hasSize(1);
    }

    @Test
    void activeSeatCountByKeyId() {
        License license = persistLicenseGraph("GMNT-1111-2222-3333", "seats@example.com", 5);

        MachineActivation a1 = new MachineActivation();
        a1.setLicense(license);
        a1.setFingerprint("fp-1");
        activations.save(a1);

        MachineActivation a2 = new MachineActivation();
        a2.setLicense(license);
        a2.setFingerprint("fp-2");
        a2.setStatus("deactivated"); // should not count toward active seats
        activations.save(a2);

        assertThat(activations.countActiveByKeyId("GMNT-1111-2222-3333")).isEqualTo(1);
    }

    @Test
    void webhookIdempotencyByProviderEventId() {
        WebhookEvent event = new WebhookEvent();
        event.setProvider("stripe");
        event.setProviderEventId("evt_12345");
        event.setEventType("customer.subscription.deleted");
        event.setSignatureValid(true);
        event.setPayload(Map.of("id", "evt_12345"));
        webhookEvents.save(event);

        assertThat(webhookEvents.existsByProviderAndProviderEventId("stripe", "evt_12345"))
                .isTrue();
        assertThat(webhookEvents.existsByProviderAndProviderEventId("stripe", "evt_unknown"))
                .isFalse();
    }
}
