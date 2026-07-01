package dev.hg.grantmint.core.activation;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.core.activation.SeatCounter.SeatActivation;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.IntRange;

/**
 * Property proof of seat Invariant 3 (docs/testing/TESTING.md): under <em>any</em> interleaving of
 * activation and deactivation attempts — arbitrary order, arbitrary repetition, fingerprints drawn
 * from a small pool so collisions actually happen — the number of active seats never exceeds
 * {@code maxSeats}, checked after every single step, not just at the end. The database-backed
 * counterpart (real locking under contention) is {@code SeatConcurrencyIntegrationTest} in
 * grantmint-server.
 */
class SeatLimitPropertyTest {

    /** The core invariant: no sequence of interleaved activate/deactivate ops ever oversubscribes. */
    @Property(tries = 3000)
    void activeSeatsNeverExceedMaxSeatsUnderAnyInterleaving(
            @ForAll @IntRange(min = 0, max = 25) int maxSeats, @ForAll("operations") List<Operation> operations) {
        SeatCounter counter = SeatCounter.forLicense("ABCD-EFGH-JKLM", maxSeats);
        Set<String> model = new HashSet<>();

        for (Operation op : operations) {
            if (op.activate()) {
                SeatActivation outcome = counter.tryActivate(op.fingerprint());
                if (outcome != SeatActivation.SEAT_LIMIT_EXCEEDED) {
                    model.add(op.fingerprint());
                }
                // A rejection may only ever happen at a full house.
                if (outcome == SeatActivation.SEAT_LIMIT_EXCEEDED) {
                    assertThat(counter.activeSeatCount()).isEqualTo(maxSeats);
                }
            } else {
                counter.deactivate(op.fingerprint());
                model.remove(op.fingerprint());
            }

            // The invariant holds after EVERY step, and the counter tracks the reference model.
            assertThat(counter.activeSeatCount())
                    .as("active seats must never exceed maxSeats=%d", maxSeats)
                    .isLessThanOrEqualTo(maxSeats);
            assertThat(counter.activeFingerprints()).isEqualTo(model);
        }
    }

    /** Re-activating already-active fingerprints is idempotent — never a new seat, never a rejection. */
    @Property(tries = 1000)
    void reactivatingAnActiveFingerprintIsIdempotent(
            @ForAll @IntRange(min = 1, max = 10) int maxSeats, @ForAll("operations") List<Operation> operations) {
        SeatCounter counter = SeatCounter.forLicense("ABCD-EFGH-JKLM", maxSeats);
        operations.forEach(op -> {
            if (op.activate()) {
                counter.tryActivate(op.fingerprint());
            } else {
                counter.deactivate(op.fingerprint());
            }
        });
        int before = counter.activeSeatCount();

        counter.activeFingerprints()
                .forEach(fp -> assertThat(counter.tryActivate(fp)).isEqualTo(SeatActivation.ALREADY_ACTIVE));

        assertThat(counter.activeSeatCount()).isEqualTo(before);
    }

    /** Deactivation frees exactly the seats it hits; the count can never go negative. */
    @Property(tries = 1000)
    void deactivationNeverUnderflowsAndFreedSeatsAreReusable(
            @ForAll @IntRange(min = 1, max = 5) int maxSeats, @ForAll("fingerprintPool") List<String> fingerprints) {
        SeatCounter counter = SeatCounter.forLicense("ABCD-EFGH-JKLM", maxSeats);
        fingerprints.forEach(counter::tryActivate);

        // Deactivate everything (including fingerprints that never activated) — count bottoms at 0.
        fingerprints.forEach(counter::deactivate);
        fingerprints.forEach(counter::deactivate);
        assertThat(counter.activeSeatCount()).isZero();

        // Every freed seat is claimable again, up to the same limit.
        long reclaimed = fingerprints.stream()
                .distinct()
                .map(counter::tryActivate)
                .filter(outcome -> outcome == SeatActivation.ACTIVATED)
                .count();
        assertThat(reclaimed)
                .isEqualTo(Math.min(maxSeats, fingerprints.stream().distinct().count()));
    }

    // ---- arbitraries ----

    /** Activate/deactivate ops over a small fingerprint pool, so re-activation and races on the same
     * device actually occur instead of every op touching a fresh fingerprint. */
    @Provide
    Arbitrary<List<Operation>> operations() {
        Arbitrary<String> fingerprints = pooledFingerprint();
        Arbitrary<Operation> ops =
                Combinators.combine(Arbitraries.of(true, false), fingerprints).as(Operation::new);
        return ops.list().ofMinSize(0).ofMaxSize(60);
    }

    @Provide
    Arbitrary<List<String>> fingerprintPool() {
        return pooledFingerprint().list().ofMinSize(0).ofMaxSize(40);
    }

    private Arbitrary<String> pooledFingerprint() {
        // 'a'–'f', length 2: a 36-element pool — small enough for frequent collisions.
        return Arbitraries.strings().withCharRange('a', 'f').ofLength(2).map(s -> "fp_" + s);
    }

    private record Operation(boolean activate, String fingerprint) {}
}
