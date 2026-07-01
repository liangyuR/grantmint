package dev.hg.grantmint.server.activation;

import java.time.OffsetDateTime;

/** Outcome of a successful deactivation: the seat is freed and the new active count reported. */
public record DeactivationResult(
        String keyId, String fingerprint, long seatsUsed, int seatsTotal, OffsetDateTime deactivatedAt) {}
