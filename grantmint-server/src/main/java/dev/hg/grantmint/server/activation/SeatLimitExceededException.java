package dev.hg.grantmint.server.activation;

/**
 * All seats are held by other fingerprints — the node-locked limit is doing its job. Rendered as a
 * {@code 409 Conflict} with code {@code seat_limit_exceeded}; a user-facing, recoverable condition
 * ("deactivate another device"), not a stop-granting-entitlements one. See
 * docs/features/ACTIVATION_AND_SEATS.md.
 */
public class SeatLimitExceededException extends RuntimeException {

    private final long seatsUsed;
    private final int seatsTotal;

    public SeatLimitExceededException(String keyId, long seatsUsed, int seatsTotal) {
        super("License " + keyId + " has reached its seat limit (" + seatsUsed + " of " + seatsTotal
                + " used). Deactivate a machine before activating a new one.");
        this.seatsUsed = seatsUsed;
        this.seatsTotal = seatsTotal;
    }

    public long seatsUsed() {
        return seatsUsed;
    }

    public int seatsTotal() {
        return seatsTotal;
    }
}
