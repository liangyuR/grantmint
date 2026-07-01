package dev.hg.grantmint.server.activation;

import java.time.OffsetDateTime;

/**
 * Outcome of a successful heartbeat: the seat's {@code last_heartbeat_at} was refreshed and the next
 * check-in deadline advertised (the policy's heartbeat interval from now).
 */
public record HeartbeatResult(
        String keyId,
        String fingerprint,
        String licenseStatus,
        String machineStatus,
        OffsetDateTime lastHeartbeatAt,
        OffsetDateTime nextHeartbeatDueBy) {}
