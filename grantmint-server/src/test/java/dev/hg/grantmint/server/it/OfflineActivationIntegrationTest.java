package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.grantmint.core.codec.Base64Url;
import dev.hg.grantmint.core.codec.CanonicalJson;
import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.crypto.Ed25519Verifier;
import dev.hg.grantmint.server.activation.ActivationCommand;
import dev.hg.grantmint.server.activation.ActivationService;
import dev.hg.grantmint.server.activation.HeartbeatReaperJob;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.lifecycle.ExpirySweepJob;
import dev.hg.grantmint.server.offline.OfflineLicenseException;
import dev.hg.grantmint.server.offline.OfflineLicenseService;
import dev.hg.grantmint.server.offline.OfflineLicenseService.ActivateRequest;
import dev.hg.grantmint.server.offline.OfflineLicenseService.ChallengeRequest;
import dev.hg.grantmint.server.offline.OfflineLicenseService.ChallengeResponse;
import dev.hg.grantmint.server.offline.OfflineLicenseService.CreateRequest;
import dev.hg.grantmint.server.offline.OfflineLicenseService.Created;
import dev.hg.grantmint.server.offline.OfflineLicenseService.Holder;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.MachineActivationRepository;
import dev.hg.grantmint.server.repo.PolicyRepository;
import dev.hg.grantmint.server.repo.ProductRepository;
import dev.hg.grantmint.server.signing.SigningKeyService;
import dev.hg.grantmint.server.validation.ValidationSnapshotLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

@SpringBootTest
class OfflineActivationIntegrationTest extends PostgresIntegrationTest {
    @Autowired
    OfflineLicenseService offline;

    @Autowired
    ProductRepository products;

    @Autowired
    PolicyRepository policies;

    @Autowired
    LicenseRepository licenses;

    @Autowired
    MachineActivationRepository activations;

    @Autowired
    SigningKeyService signing;

    @Autowired
    ActivationService legacy;

    @Autowired
    ValidationSnapshotLoader validation;

    @Autowired
    HeartbeatReaperJob reaper;

    @Autowired
    ExpirySweepJob expiry;

    @Autowired
    JdbcTemplate jdbc;

    @TempDir
    Path keyDir;

    @Test
    @SuppressWarnings("unchecked")
    void creationHasNoCertificateAndActivationRetriesReturnTheSameDeviceBoundArtifact() throws Exception {
        Fixture fixture = fixture();
        assertThat(licenses.findById(fixture.license().licenseId())
                        .orElseThrow()
                        .getSignedToken())
                .isNull();
        assertCode(() -> validation.load(fixture.license().keyId()), "offline_requires_v2");
        KeyPair device = Ed25519Keys.generate(new java.security.SecureRandom());
        var challenge = challenge(fixture, device, "first");
        var request = request(fixture, device, challenge);
        var result = offline.activate(request);
        assertThat(offline.activate(request)).isEqualTo(result);
        String[] segments = result.token().split("\\.");
        assertThat(new Ed25519Verifier(fixture.signer().getPublic())
                        .verify(
                                (segments[0] + "." + segments[1]).getBytes(StandardCharsets.US_ASCII),
                                Base64Url.decode(segments[2])))
                .isTrue();
        Map<String, Object> claims = (Map<String, Object>) CanonicalJson.parse(Base64Url.decode(segments[1]));
        assertThat(claims)
                .containsEntry("ver", 2L)
                .containsEntry("product_id", fixture.productId().toString())
                .containsEntry("exp", fixture.license().expiresAt().toEpochSecond())
                .containsEntry("seat", 1L)
                .containsEntry("binding_version", 1L)
                .containsEntry("mode", "offline_device");
        assertThat(activations.countActiveByKeyId(result.keyId())).isEqualTo(1);
        var changedKey = new ActivateRequest(
                request.productId(),
                request.licenseId(),
                request.challengeId(),
                request.signature(),
                UUID.randomUUID().toString());
        assertCode(() -> offline.activate(changedKey), "idempotency_conflict");
    }

    @Test
    void sameDeviceCanRecoverCertificateUsingANewChallengeAfterResponseLoss() throws Exception {
        Fixture fixture = fixture();
        KeyPair device = Ed25519Keys.generate(new java.security.SecureRandom());
        var firstChallenge = challenge(fixture, device, "recover");
        var original = offline.activate(request(fixture, device, firstChallenge));
        jdbc.update(
                "update offline_activation_challenges set expires_at = ? where id = ?",
                OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(1),
                firstChallenge.challengeId());
        var nextChallenge = challenge(fixture, device, "recover");
        var recovered = offline.activate(request(fixture, device, nextChallenge));
        assertThat(recovered.token()).isEqualTo(original.token());
        assertThat(recovered.timeReceipt()).isNotEqualTo(original.timeReceipt());
        assertThat(activations.countActiveByKeyId(original.keyId())).isEqualTo(1);
        var changedFingerprint = input(fixture, device, "changed");
        assertCode(() -> offline.challenge(changedFingerprint), "device_already_bound");
    }

    @Test
    void concurrentDifferentDevicesCannotBothBindTheSameLicense() throws Exception {
        Fixture fixture = fixture();
        KeyPair a = Ed25519Keys.generate(new java.security.SecureRandom());
        KeyPair b = Ed25519Keys.generate(new java.security.SecureRandom());
        var first = request(fixture, a, challenge(fixture, a, "a"));
        var second = request(fixture, b, challenge(fixture, b, "b"));
        CountDownLatch start = new CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var results = List.of(first, second).stream()
                    .map(req -> pool.submit(() -> {
                        start.await();
                        try {
                            offline.activate(req);
                            return "ok";
                        } catch (OfflineLicenseException e) {
                            return e.code();
                        }
                    }))
                    .toList();
            start.countDown();
            assertThat(List.of(results.get(0).get(), results.get(1).get()))
                    .containsExactlyInAnyOrder("ok", "device_already_bound");
        }
        assertThat(activations.countActiveByKeyId(fixture.license().keyId())).isEqualTo(1);
    }

    @Test
    void invalidProofOrExpiredChallengeCannotActivateOrConsumeASeat() throws Exception {
        Fixture fixture = fixture();
        KeyPair device = Ed25519Keys.generate(new java.security.SecureRandom());
        var input = input(fixture, device, "proof");
        assertCode(
                () -> offline.challenge(new ChallengeRequest(
                        input.productId(),
                        input.licenseId(),
                        "0".repeat(64),
                        input.devicePublicKey(),
                        input.fingerprintHash(),
                        1)),
                "invalid_activation_credentials");
        assertCode(
                () -> offline.challenge(new ChallengeRequest(
                        UUID.randomUUID(),
                        input.licenseId(),
                        input.activationSecret(),
                        input.devicePublicKey(),
                        input.fingerprintHash(),
                        1)),
                "invalid_activation_credentials");
        var challenge = offline.challenge(input);
        var request = request(fixture, device, challenge);
        assertCode(
                () -> offline.activate(new ActivateRequest(
                        request.productId(),
                        request.licenseId(),
                        request.challengeId(),
                        Base64Url.encode(new byte[64]),
                        request.idempotencyKey())),
                "invalid_device_proof");
        jdbc.update(
                "update offline_activation_challenges set expires_at = ? where id = ?",
                OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(1),
                challenge.challengeId());
        assertCode(() -> offline.activate(request), "challenge_expired");
        assertThat(licenses.findById(request.licenseId()).orElseThrow().getBindingVersion())
                .isZero();
        assertThat(activations.countActiveByKeyId(fixture.license().keyId())).isZero();
    }

    @Test
    void unavailableSigningKeyRollsBackBindingAndTheChallengeCanBeRetried() throws Exception {
        Fixture fixture = fixture();
        KeyPair device = Ed25519Keys.generate(new java.security.SecureRandom());
        var request = request(fixture, device, challenge(fixture, device, "rollback"));
        byte[] seed = Files.readAllBytes(fixture.seedFile());
        Files.delete(fixture.seedFile());
        assertThatThrownBy(() -> offline.activate(request)).isInstanceOf(RuntimeException.class);
        assertThat(licenses.findById(request.licenseId()).orElseThrow().getBindingVersion())
                .isZero();
        assertThat(activations.countActiveByKeyId(fixture.license().keyId())).isZero();
        Files.write(fixture.seedFile(), seed);
        Files.setPosixFilePermissions(fixture.seedFile(), PosixFilePermissions.fromString("rw-------"));
        assertThat(offline.activate(request).token()).isNotBlank();
    }

    @Test
    void offlineBindingSurvivesHeartbeatTimeoutAndLegacyEndpointsCannotReleaseIt() throws Exception {
        Fixture fixture = fixture();
        KeyPair device = Ed25519Keys.generate(new java.security.SecureRandom());
        var activated = offline.activate(request(fixture, device, challenge(fixture, device, "long-offline")));
        jdbc.update(
                "update machine_activations set last_heartbeat_at = ? where license_id = ?",
                OffsetDateTime.now(ZoneOffset.UTC).minusYears(1),
                activated.licenseId());
        reaper.reap();
        assertThat(activations.countActiveByKeyId(activated.keyId())).isEqualTo(1);
        assertCode(() -> validation.load(activated.keyId()), "offline_requires_v2");
        assertCode(
                () -> legacy.activate(new ActivationCommand(
                        activated.keyId(), fixture.productId(), "other", null, null, null, "test", null)),
                "offline_requires_v2");
        UUID activationId =
                activations.findByLicense_Id(activated.licenseId()).getFirst().getId();
        assertCode(
                () -> legacy.deactivate(activated.keyId(), fixture.productId(), "other", "test", null),
                "offline_requires_v2");
        assertCode(() -> legacy.heartbeat(activated.keyId(), fixture.productId(), "other"), "offline_requires_v2");
        assertCode(() -> legacy.forceDeactivate(activationId, activated.keyId(), "test"), "offline_requires_v2");
        assertThat(activations.countActiveByKeyId(activated.keyId())).isEqualTo(1);
    }

    @Test
    void offlineExpiryIgnoresPolicyGraceAndRejectsFurtherActivation() throws Exception {
        Fixture fixture = fixture();
        KeyPair device = Ed25519Keys.generate(new java.security.SecureRandom());
        var activated = offline.activate(request(fixture, device, challenge(fixture, device, "expiry")));
        jdbc.update(
                "update licenses set expires_at = ? where id = ?",
                OffsetDateTime.now(ZoneOffset.UTC).minusSeconds(1),
                activated.licenseId());
        expiry.sweep();
        assertThat(licenses.findById(activated.licenseId()).orElseThrow().getStatus())
                .isEqualTo(LicenseStatus.EXPIRED);
        assertCode(() -> challenge(fixture, device, "expiry"), "license_unavailable");
    }

    private Fixture fixture() throws Exception {
        Product product = new Product();
        product.setSlug("offline-" + UUID.randomUUID());
        product.setName("Offline fixture");
        products.saveAndFlush(product);
        Policy policy = new Policy();
        policy.setProduct(product);
        policy.setCode("offline");
        policy.setName("Offline");
        policy.setMaxSeats(8);
        policy.setGracePeriodDays(30);
        policy.setHeartbeatIntervalSeconds(60);
        policies.saveAndFlush(policy);
        KeyPair signer = Ed25519Keys.generate(new java.security.SecureRandom());
        Path file = keyDir.resolve(product.getId() + ".hex");
        Files.writeString(file, HexFormat.of().formatHex(Ed25519Keys.encodePrivateKey(signer.getPrivate())));
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        signing.register(
                product.getId(),
                "key-" + product.getId(),
                "file:" + file,
                Ed25519Keys.encodePublicKey(signer.getPublic()),
                true);
        var created = offline.create(
                new CreateRequest(
                        product.getId(),
                        policy.getId(),
                        new Holder("Test", "test@example.invalid"),
                        OffsetDateTime.now(ZoneOffset.UTC).plusDays(30)),
                "test");
        return new Fixture(product.getId(), created, signer, file);
    }

    private ChallengeRequest input(Fixture fixture, KeyPair device, String fingerprint) {
        return new ChallengeRequest(
                fixture.productId(),
                fixture.license().licenseId(),
                fixture.license().activationSecret(),
                Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(device.getPublic())),
                dev.hg.grantmint.core.token.OfflineDeviceTokens.keyHash(fingerprint.getBytes(StandardCharsets.UTF_8)),
                1);
    }

    private ChallengeResponse challenge(Fixture fixture, KeyPair device, String fingerprint) {
        return offline.challenge(input(fixture, device, fingerprint));
    }

    private ActivateRequest request(Fixture fixture, KeyPair device, ChallengeResponse challenge) {
        String signature = Base64Url.encode(
                new Ed25519Signer(device.getPrivate(), "device").sign(Base64Url.decode(challenge.message())));
        return new ActivateRequest(
                fixture.productId(),
                fixture.license().licenseId(),
                challenge.challengeId(),
                signature,
                UUID.randomUUID().toString());
    }

    private static void assertCode(Runnable action, String code) {
        assertThatThrownBy(action::run)
                .isInstanceOf(OfflineLicenseException.class)
                .hasMessage(code);
    }

    private record Fixture(UUID productId, Created license, KeyPair signer, Path seedFile) {}
}
