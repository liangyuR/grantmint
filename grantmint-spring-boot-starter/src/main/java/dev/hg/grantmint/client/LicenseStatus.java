package dev.hg.grantmint.client;

import java.time.Instant;
import java.util.Map;

/**
 * The result of a license check — offline, online, or hybrid. {@code valid} is the go/no-go;
 * {@code reason} says why not (or {@link Reason#VALID}); {@code fromCache} marks an online result
 * served from the client-side TTL cache rather than a live call.
 */
public record LicenseStatus(
        boolean valid,
        Reason reason,
        String keyId,
        String holderEmail,
        Instant expiresAt,
        Map<String, Object> entitlements,
        boolean fromCache) {

    public LicenseStatus {
        entitlements = entitlements == null ? Map.of() : Map.copyOf(entitlements);
    }

    /**
     * Why a check passed or failed. The offline reasons deliberately collapse the verifier's
     * structural taxonomy (malformed / algorithm-confused / wrong-typed / forged) into
     * {@link #INVALID_SIGNATURE} — which defect an untrustworthy token exhibits is not actionable
     * for an app. {@link #UNSUPPORTED_VERSION} stays distinct because that credential is authentic:
     * the right user action is "update this app", not "your license is bad".
     */
    public enum Reason {
        VALID,
        /** Malformed or forged token — never acceptable. */
        INVALID_SIGNATURE,
        /** An authentic token whose format version this verifier does not know — update the app. */
        UNSUPPORTED_VERSION,
        /** An authentic token, but for a different product than this app is configured for. */
        WRONG_PRODUCT,
        EXPIRED,
        NOT_YET_VALID,
        REVOKED,
        SUSPENDED,
        /** Issued but never activated (online {@code license_inactive}). */
        INACTIVE,
        SEAT_LIMIT_EXCEEDED,
        /** The online check could not be performed; {@code fail-open} decides what that means. */
        SERVER_UNREACHABLE
    }

    public static LicenseStatus invalid(Reason reason, String keyId) {
        return new LicenseStatus(false, reason, keyId, null, null, Map.of(), false);
    }
}
