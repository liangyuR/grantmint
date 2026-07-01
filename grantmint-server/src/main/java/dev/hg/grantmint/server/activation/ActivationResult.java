package dev.hg.grantmint.server.activation;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Outcome of a successful activation. {@code reactivated} distinguishes the idempotent re-claim of an
 * already-held seat (HTTP 200) from a fresh claim (HTTP 201). {@code activatedAt} is the row's
 * original activation instant — re-activating a previously deactivated fingerprint reuses its row
 * (UNIQUE(license_id, fingerprint)), so the timestamp reflects the device's first activation.
 */
public record ActivationResult(
        String keyId,
        UUID activationId,
        String fingerprint,
        String machineStatus,
        boolean reactivated,
        long seatsUsed,
        int seatsTotal,
        OffsetDateTime activatedAt,
        int heartbeatIntervalSeconds,
        OffsetDateTime nextHeartbeatDueBy) {}
