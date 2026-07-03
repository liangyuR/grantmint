package dev.hg.grantmint.server.validation;

import dev.hg.grantmint.server.domain.LicenseStatus;
import java.util.Map;
import java.util.UUID;

/**
 * The pre-computed, cacheable view of a license needed to answer an online validation, captured once
 * on a cache miss and reused on the hot path.
 *
 * <p>{@code signatureValid} is time-independent — the signed token's bytes never change — so it is
 * computed once and cached. {@code status} is the field that can go <em>stale</em>: a revoke or
 * suspend mutates the row but not this snapshot, so a cached {@code ACTIVE} keeps validating until
 * the entry's TTL elapses (the revocation-latency ceiling) or it is explicitly evicted. {@code
 * expEpochSecond}/{@code nbfEpochSecond} are re-evaluated against the current clock on every request
 * so a snapshot cached just before expiry still flips to expired at the right instant.
 *
 * <p>{@code productSlug} rides along for the metrics {@code product} tag — the low-cardinality
 * dimension the catalog allows where the key id itself never may be (MONITORING_LOGGING.md).
 */
public record ValidationSnapshot(
        UUID productId,
        String productSlug,
        LicenseStatus status,
        boolean signatureValid,
        Long nbfEpochSecond,
        Long expEpochSecond,
        int maxSeats,
        Map<String, Object> entitlements) {

    public ValidationSnapshot {
        entitlements = entitlements == null ? Map.of() : Map.copyOf(entitlements);
    }
}
