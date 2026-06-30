package dev.hg.grantmint.server.validation;

import java.time.OffsetDateTime;
import java.util.Map;

/**
 * The successful outcome of an online validation: the license is authentic, active, and within its
 * temporal window. Carries the live entitlement snapshot (the database truth, which a later policy
 * edit never mutates) for the caller to gate features on.
 *
 * @param status the wire status string (always {@code active} on success)
 * @param keyId the validated license key id
 * @param expiresAt the expiry instant, or null for a perpetual license
 * @param entitlements the live entitlement map
 * @param checkedAt the server time the decision was made
 */
public record ValidationView(
        String status,
        String keyId,
        OffsetDateTime expiresAt,
        Map<String, Object> entitlements,
        OffsetDateTime checkedAt) {}
