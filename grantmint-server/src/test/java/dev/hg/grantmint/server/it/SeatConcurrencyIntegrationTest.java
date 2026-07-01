package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.server.activation.ActivationCommand;
import dev.hg.grantmint.server.activation.ActivationService;
import dev.hg.grantmint.server.activation.SeatLimitExceededException;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.issuance.IssuanceCommand;
import dev.hg.grantmint.server.issuance.IssuanceService;
import dev.hg.grantmint.server.repo.MachineActivationRepository;
import dev.hg.grantmint.server.repo.PolicyRepository;
import dev.hg.grantmint.server.repo.ProductRepository;
import dev.hg.grantmint.server.signing.SigningKeyService;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * The database-backed half of seat Invariant 3 (docs/testing/TESTING.md): seat enforcement must hold
 * under real concurrent contention. The mechanism under test is the pessimistic row lock
 * ({@code SELECT … FOR UPDATE} on the license) that serializes the count-then-insert inside
 * {@code ActivationService.activate} — exactly what an in-memory database would fake, hence real
 * PostgreSQL via Testcontainers and, unlike the sibling flow test, <b>no</b> {@code @Transactional}
 * on the class: every service call must run (and commit) its own transaction for the lock to matter.
 */
@SpringBootTest
class SeatConcurrencyIntegrationTest extends PostgresIntegrationTest {

    @Autowired
    private ProductRepository products;

    @Autowired
    private PolicyRepository policies;

    @Autowired
    private SigningKeyService signingKeys;

    @Autowired
    private IssuanceService issuance;

    @Autowired
    private ActivationService activations;

    @Autowired
    private MachineActivationRepository activationRows;

    @TempDir
    Path keyDir;

    @Test
    void aThunderingHerdNeverOversubscribesTheSeats() throws Exception {
        int maxSeats = 3;
        int threads = 20;
        Fixture fx = fixture("seat-herd", maxSeats);

        long acquired =
                race(threads, i -> activate(fx, "fp_herd_" + HexFormat.of().toHexDigits(i, 4)));

        assertThat(acquired).isEqualTo(maxSeats);
        assertThat(activationRows.countActiveByKeyId(fx.keyId())).isEqualTo(maxSeats);
    }

    @Test
    void parallelActivationsOnTheLastSeatExactlyOneWins() throws Exception {
        Fixture fx = fixture("seat-last", 2);

        // Occupy all but the last seat, then race distinct fingerprints for it.
        assertThat(activate(fx, "fp_last_occupant")).isTrue();
        long acquired = race(8, i -> activate(fx, "fp_last_racer_" + i));

        assertThat(acquired).isEqualTo(1);
        assertThat(activationRows.countActiveByKeyId(fx.keyId())).isEqualTo(2);
    }

    @Test
    void parallelReactivationOfTheSameFingerprintConsumesOneSeat() throws Exception {
        Fixture fx = fixture("seat-idem", 2);

        // Every racer is the SAME device: idempotent re-activation must never double-claim, whether
        // it lands on the fresh-insert path or the already-active path.
        long succeeded = race(8, i -> activate(fx, "fp_same_device"));

        assertThat(succeeded).isEqualTo(8); // idempotent — nobody is rejected
        assertThat(activationRows.countActiveByKeyId(fx.keyId())).isEqualTo(1);
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    /** Release {@code threads} concurrent attempts at once; count how many claimed a seat. */
    private long race(int threads, ThrowingPredicate attempt) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<Boolean>> futures = IntStream.range(0, threads)
                    .mapToObj(i -> pool.submit(() -> {
                        start.await();
                        return attempt.test(i);
                    }))
                    .toList();
            start.countDown();
            long acquired = 0;
            for (Future<Boolean> f : futures) {
                if (f.get()) {
                    acquired++;
                }
            }
            return acquired;
        } finally {
            pool.shutdown();
        }
    }

    private boolean activate(Fixture fx, String fingerprint) {
        try {
            activations.activate(
                    new ActivationCommand(fx.keyId(), fx.productId(), fingerprint, null, null, null, "test-key", null));
            return true;
        } catch (SeatLimitExceededException rejected) {
            return false;
        }
    }

    private interface ThrowingPredicate {
        boolean test(int i) throws Exception;
    }

    /** Committed (non-rolled-back) product + signing key + policy + issued license. */
    private Fixture fixture(String slug, int maxSeats) throws IOException {
        Product product = new Product();
        product.setSlug(slug + "-" + UUID.randomUUID().toString().substring(0, 8));
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
        policy.setMaxSeats(maxSeats);
        policy.setDurationDays(365);
        UUID policyId = policies.save(policy).getId();

        String keyId = issuance.issue(new IssuanceCommand(
                        productId, policyId, "Jane", "jane@example.com", null, null, null, "test-key", null))
                .keyId();
        return new Fixture(productId, keyId);
    }

    private record Fixture(UUID productId, String keyId) {}
}
