package dev.hg.grantmint.client;

import dev.hg.grantmint.client.verify.OfflineTokenVerifier;
import dev.hg.grantmint.client.verify.TokenVerificationException;
import dev.hg.grantmint.client.verify.VerifiedToken;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * The SDK's entry point: offline verification (fast, air-gap-safe), online validation
 * (authoritative — revocation, suspension, seats), and {@link #current()} for the license this
 * instance is configured to run under.
 *
 * <p><b>Hybrid semantics.</b> Offline is the baseline: a token that fails signature or expiry is
 * dead regardless of what the server would say. When the offline check passes, the online layer
 * overlays database truth, cached for the configured TTL. An unreachable server resolves per
 * {@code fail-open}: {@code false} (default) denies, {@code true} falls back to the offline
 * verdict — the documented offline↔online tradeoff, decided by the operator. See
 * docs/features/CLIENT_SDK.md.
 */
public final class LicenseValidator {

    private final OfflineTokenVerifier verifier;
    private final OnlineLicenseClient online; // null in offline-only mode
    private final GrantmintClientProperties props;
    private final Clock clock;

    private volatile CachedStatus cachedOnline;

    private LicenseValidator(
            OfflineTokenVerifier verifier, OnlineLicenseClient online, GrantmintClientProperties props, Clock clock) {
        this.verifier = verifier;
        this.online = online;
        this.props = props;
        this.clock = clock;
    }

    /** Purely offline: signature + temporal window against the embedded public key. */
    public static LicenseValidator offlineOnly(OfflineTokenVerifier verifier, GrantmintClientProperties props) {
        return new LicenseValidator(verifier, null, props, Clock.systemUTC());
    }

    /** Offline baseline + online overlay (activation/seat/revocation truth). */
    public static LicenseValidator hybrid(OfflineTokenVerifier verifier, GrantmintClientProperties props) {
        return new LicenseValidator(verifier, new OnlineLicenseClient(props), props, Clock.systemUTC());
    }

    /** Test seam with explicit collaborators. */
    static LicenseValidator of(
            OfflineTokenVerifier verifier, OnlineLicenseClient online, GrantmintClientProperties props, Clock clock) {
        return new LicenseValidator(verifier, online, props, clock);
    }

    /** Verify a token offline — no network, ever. */
    public LicenseStatus verifyOffline(String token) {
        VerifiedToken verified;
        try {
            // Product binding happens inside the verifier, between the version gate and the temporal
            // window — the reference verifier's step order, so an expired token for another product
            // is WRONG_PRODUCT here exactly as it is there (audit 2026-07-05, GRANTMINT-145).
            verified = verifier.verify(token, expectedProduct());
        } catch (TokenVerificationException refused) {
            // keyId is non-null only for post-signature refusals (wrong product, expired, not yet
            // valid, unsupported version) — an authentic credential callers may want to name.
            return LicenseStatus.invalid(reasonOf(refused.reason()), refused.keyId());
        }
        return new LicenseStatus(
                true,
                LicenseStatus.Reason.VALID,
                verified.keyId(),
                verified.holderEmail(),
                verified.expiresAt(),
                verified.entitlements(),
                false);
    }

    /** Validate online — authoritative, requires connectivity; results cached for the TTL. */
    public LicenseStatus validateOnline(String keyId, String fingerprint) {
        if (online == null) {
            throw new IllegalStateException("online validation is not configured (mode=offline)");
        }
        return online.validate(keyId, fingerprint);
    }

    /**
     * The status of the configured license ({@code grantmint.client.license-token}): the offline
     * verdict, overlaid — in hybrid/online mode — with the TTL-cached online answer and the
     * fail-open policy.
     */
    public LicenseStatus current() {
        String token = props.getLicenseToken();
        if (token == null || token.isBlank()) {
            return LicenseStatus.invalid(LicenseStatus.Reason.INVALID_SIGNATURE, props.getKeyId());
        }
        LicenseStatus offline = verifyOffline(token);
        if (!offline.valid() || online == null) {
            return offline;
        }

        CachedStatus cached = this.cachedOnline;
        Instant now = clock.instant();
        if (cached != null && cached.freshAt(now, props.getCache().getTtl())) {
            return cached.status();
        }
        LicenseStatus live = online.validate(keyIdFor(offline), null);
        if (live.reason() == LicenseStatus.Reason.SERVER_UNREACHABLE) {
            // The operator's call: deny (safe default) or trust the offline verdict.
            return props.isFailOpen() ? offline : live;
        }
        this.cachedOnline = new CachedStatus(withCacheFlag(live), now);
        return live;
    }

    private String keyIdFor(LicenseStatus offline) {
        return props.getKeyId() != null && !props.getKeyId().isBlank() ? props.getKeyId() : offline.keyId();
    }

    private static LicenseStatus withCacheFlag(LicenseStatus status) {
        return new LicenseStatus(
                status.valid(),
                status.reason(),
                status.keyId(),
                status.holderEmail(),
                status.expiresAt(),
                status.entitlements(),
                true);
    }

    /** The configured product to bind against, or null when the operator configured none. */
    private String expectedProduct() {
        String product = props.getProduct();
        return product == null || product.isBlank() ? null : product;
    }

    private static LicenseStatus.Reason reasonOf(TokenVerificationException.Reason reason) {
        return switch (reason) {
            case EXPIRED -> LicenseStatus.Reason.EXPIRED;
            case NOT_YET_VALID -> LicenseStatus.Reason.NOT_YET_VALID;
            case WRONG_PRODUCT -> LicenseStatus.Reason.WRONG_PRODUCT;
                // Authentic credential, unknown format — distinct so the app can say "update me"
                // (2026-07-05 audit, GRANTMINT-149). The structural reasons below stay collapsed:
                // which defect a forged token exhibits is not actionable for an app.
            case UNSUPPORTED_VERSION -> LicenseStatus.Reason.UNSUPPORTED_VERSION;
            case MALFORMED, ALG_NOT_ALLOWED, WRONG_TYPE, INVALID_SIGNATURE -> LicenseStatus.Reason.INVALID_SIGNATURE;
        };
    }

    private record CachedStatus(LicenseStatus status, Instant at) {
        boolean freshAt(Instant now, Duration ttl) {
            return at.plus(ttl).isAfter(now);
        }
    }
}
