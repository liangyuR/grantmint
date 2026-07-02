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
            verified = verifier.verify(token);
        } catch (TokenVerificationException refused) {
            return LicenseStatus.invalid(reasonOf(refused.reason()), null);
        }
        // Product binding: a valid token for someone else's product is not a license for this app.
        if (props.getProduct() != null
                && !props.getProduct().isBlank()
                && !props.getProduct().equals(verified.product())) {
            return LicenseStatus.invalid(LicenseStatus.Reason.INVALID_SIGNATURE, verified.keyId());
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

    private static LicenseStatus.Reason reasonOf(TokenVerificationException.Reason reason) {
        return switch (reason) {
            case EXPIRED -> LicenseStatus.Reason.EXPIRED;
            case NOT_YET_VALID -> LicenseStatus.Reason.NOT_YET_VALID;
            case MALFORMED, INVALID_SIGNATURE, WRONG_PRODUCT -> LicenseStatus.Reason.INVALID_SIGNATURE;
        };
    }

    private record CachedStatus(LicenseStatus status, Instant at) {
        boolean freshAt(Instant now, Duration ttl) {
            return at.plus(ttl).isAfter(now);
        }
    }
}
