package dev.hg.grantmint.server.activation;

import java.util.Map;
import java.util.UUID;

/**
 * Input to {@link ActivationService#activate}. {@code machineName}, {@code platform} and
 * {@code metadata} are free-form operator-console decoration only — never part of the fingerprint,
 * never involved in seat counting (docs/features/ACTIVATION_AND_SEATS.md).
 *
 * @param keyId the license's short online key id
 * @param requesterProductId the product the validation key is scoped to (cross-product guard)
 * @param fingerprint the opaque, client-computed device fingerprint
 * @param machineName optional human-readable device label
 * @param platform optional platform hint, e.g. {@code macos}
 * @param metadata optional free-form dashboard metadata
 * @param actor the API-key id for audit attribution
 * @param ipAddress the originating request IP (nullable)
 */
public record ActivationCommand(
        String keyId,
        UUID requesterProductId,
        String fingerprint,
        String machineName,
        String platform,
        Map<String, Object> metadata,
        String actor,
        String ipAddress) {}
