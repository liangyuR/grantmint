package dev.hg.grantmint.core.activation;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * The pure, in-memory model of node-locked seat semantics — the executable specification the
 * server's transactional activation path (and the jqwik property suite) is held to. A seat is a
 * distinct active fingerprint; the invariant is {@code activeSeatCount() <= maxSeats}, always:
 *
 * <ul>
 *   <li>activating a new fingerprint consumes a seat only below the limit, else it is rejected;
 *   <li>re-activating an already-active fingerprint is idempotent — no seat consumed, never
 *       rejected, even at the limit;
 *   <li>deactivating an active fingerprint frees exactly one seat; deactivating anything else is a
 *       no-op and the count never goes negative;
 *   <li>a deactivated fingerprint may re-activate, subject to the same limit as a new one.
 * </ul>
 *
 * <p>This class is deliberately framework-free and unsynchronized: it models the <em>semantics</em>,
 * not the concurrency control. The server enforces the same invariant under contention with a row
 * lock — proven against real PostgreSQL by {@code SeatConcurrencyIntegrationTest}. See
 * docs/features/ACTIVATION_AND_SEATS.md and docs/testing/TESTING.md (Invariant 3).
 */
public final class SeatCounter {

    /** Outcome of a single activation attempt. */
    public enum SeatActivation {
        /** A free seat was claimed. */
        ACTIVATED,
        /** The fingerprint already held a seat — idempotent, nothing changed. */
        ALREADY_ACTIVE,
        /** All seats are held by other fingerprints. */
        SEAT_LIMIT_EXCEEDED
    }

    private final String keyId;
    private final int maxSeats;
    private final Set<String> active = new LinkedHashSet<>();

    private SeatCounter(String keyId, int maxSeats) {
        if (maxSeats < 0) {
            throw new IllegalArgumentException("maxSeats must be >= 0, got " + maxSeats);
        }
        this.keyId = Objects.requireNonNull(keyId, "keyId");
        this.maxSeats = maxSeats;
    }

    public static SeatCounter forLicense(String keyId, int maxSeats) {
        return new SeatCounter(keyId, maxSeats);
    }

    /** Attempt to claim (or idempotently re-claim) a seat for the fingerprint. */
    public SeatActivation tryActivate(String fingerprint) {
        Objects.requireNonNull(fingerprint, "fingerprint");
        if (active.contains(fingerprint)) {
            return SeatActivation.ALREADY_ACTIVE;
        }
        if (active.size() >= maxSeats) {
            return SeatActivation.SEAT_LIMIT_EXCEEDED;
        }
        active.add(fingerprint);
        return SeatActivation.ACTIVATED;
    }

    /** Free the fingerprint's seat; {@code false} (and no change) when it held none. */
    public boolean deactivate(String fingerprint) {
        return active.remove(fingerprint);
    }

    public int activeSeatCount() {
        return active.size();
    }

    /** The currently active fingerprints, in activation order. */
    public Set<String> activeFingerprints() {
        return Set.copyOf(active);
    }

    public String keyId() {
        return keyId;
    }

    public int maxSeats() {
        return maxSeats;
    }
}
