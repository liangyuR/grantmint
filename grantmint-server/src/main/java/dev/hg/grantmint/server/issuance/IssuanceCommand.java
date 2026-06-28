package dev.hg.grantmint.server.issuance;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * A request to mint a license. {@code productId} is the product the authenticated issuance key is
 * scoped to (the cross-product guard compares it against the policy's product); {@code policyId} is
 * the tier to mint from. Overrides are optional — a null {@code expiresAtOverride} uses the policy's
 * duration, a null {@code seatOverride} uses the policy's seat count.
 *
 * @param actor the acting API-key id (for the audit trail)
 * @param ipAddress the originating request IP, or null
 */
public record IssuanceCommand(
        UUID productId,
        UUID policyId,
        String holderName,
        String holderEmail,
        OffsetDateTime expiresAtOverride,
        Integer seatOverride,
        String externalRef,
        String actor,
        String ipAddress) {}
