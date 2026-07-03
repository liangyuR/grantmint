package dev.hg.grantmint.server.validation;

import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.metrics.GrantmintMetrics;
import io.micrometer.core.instrument.Timer;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * The online validation entrypoint — the authoritative, network-required counterpart to the offline
 * token check. It layers <em>database truth</em> (revocation, suspension, expiry, activation status)
 * on top of the cryptographic verification the {@code grantmint-core} verifier performs offline, and
 * is the only place that can reject a license whose token still passes pure signature verification.
 *
 * <p>Flow: resolve a cached {@link ValidationSnapshot} (loaded once per TTL via {@link
 * ValidationSnapshotLoader}), enforce cross-product isolation, then run the pure {@link #decide}
 * predicate over the snapshot and the current clock. A healthy license returns a {@link
 * ValidationView}; an authentic-but-unusable one throws {@link LicenseNotValidException} (422); an
 * unknown key id throws {@link NoSuchElementException} (404). See
 * docs/architecture/ARCHITECTURE.md (validation flow).
 *
 * <p><b>v1 scope.</b> The {@code fingerprint} is accepted but not yet matched against an activation —
 * machine binding and seat reporting land in M6. Status mutation (suspend/reinstate/revoke), and the
 * cache eviction those trigger, land in M7; until then a revoked license is enforced within the cache
 * TTL (the revocation-latency ceiling) or via an explicit {@link ValidationCache#evict}.
 */
@Service
public class ValidationService {

    /** A revoked license — terminal; never valid again. */
    public static final String LICENSE_REVOKED = "license_revoked";
    /** A suspended license — temporarily blocked, reinstatable. */
    public static final String LICENSE_SUSPENDED = "license_suspended";
    /** Past its expiry (by database status or token {@code exp}). */
    public static final String LICENSE_EXPIRED = "license_expired";
    /** Before its not-before instant. */
    public static final String LICENSE_NOT_YET_VALID = "license_not_yet_valid";
    /** Issued but never activated (status still {@code created}). */
    public static final String LICENSE_INACTIVE = "license_inactive";
    /** The stored token failed signature/structure verification — a server-integrity fault. */
    public static final String LICENSE_INVALID = "license_invalid";

    private final ValidationCache cache;
    private final ValidationSnapshotLoader loader;
    private final Clock clock;
    private final GrantmintMetrics metrics;

    public ValidationService(
            ValidationCache cache, ValidationSnapshotLoader loader, Clock clock, GrantmintMetrics metrics) {
        this.cache = cache;
        this.loader = loader;
        this.clock = clock;
        this.metrics = metrics;
    }

    /**
     * Validate a license online.
     *
     * @param keyId the license key id to validate
     * @param requesterProductId the product the validation key is scoped to; the license must belong
     *     to it, or the call 404s rather than leaking another product's license
     * @param fingerprint the optional machine fingerprint (accepted, not yet enforced — M6)
     * @throws NoSuchElementException if no such license is visible to this product (404)
     * @throws LicenseNotValidException if the license is authentic but not currently valid (422)
     */
    public ValidationView validate(String keyId, UUID requesterProductId, String fingerprint) {
        Timer.Sample sample = metrics.start();
        boolean[] loaded = {false};
        ValidationSnapshot snapshot;
        try {
            snapshot = cache.get(keyId, id -> {
                loaded[0] = true;
                return loader.load(id);
            });
        } catch (NoSuchElementException unknownKeyId) {
            // No snapshot, so no product to attribute the miss to — a fixed low-cardinality tag.
            metrics.recordValidation(sample, "unknown", false, RESULT_NOT_FOUND);
            throw unknownKeyId;
        }
        boolean cacheHit = !loaded[0];

        // Cross-product isolation: a product's validation key may only see its own licenses.
        if (requesterProductId != null && !requesterProductId.equals(snapshot.productId())) {
            metrics.recordValidation(sample, snapshot.productSlug(), cacheHit, RESULT_NOT_FOUND);
            throw new NoSuchElementException("License not found: " + keyId);
        }

        long now = clock.instant().getEpochSecond();
        Decision decision = decide(snapshot, now);
        if (!decision.valid()) {
            metrics.recordValidation(sample, snapshot.productSlug(), cacheHit, metricResult(decision.code()));
            throw new LicenseNotValidException(decision.code(), messageFor(decision.code(), keyId, snapshot));
        }
        metrics.recordValidation(sample, snapshot.productSlug(), cacheHit, "valid");

        OffsetDateTime expiresAt = snapshot.expEpochSecond() == null
                ? null
                : OffsetDateTime.ofInstant(Instant.ofEpochSecond(snapshot.expEpochSecond()), ZoneOffset.UTC);
        return new ValidationView(
                LicenseStatus.ACTIVE.wire(),
                keyId,
                expiresAt,
                snapshot.entitlements(),
                OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));
    }

    /**
     * The pure validation predicate — given a snapshot and the current epoch second, decide whether
     * the license is usable and, if not, why. Extracted as a side-effect-free static so the full
     * decision matrix can be property-tested without a database.
     *
     * <p>Precedence is deliberate and reflects the online-primary model: a terminal/blocked database
     * status (revoked, suspended) wins over everything else; an unactivated or db-expired status next;
     * then the token's own signature integrity; finally the temporal window. Revocation therefore
     * always reports as {@code license_revoked} even if the token also happens to be expired.
     */
    static Decision decide(ValidationSnapshot snapshot, long nowEpochSecond) {
        switch (snapshot.status()) {
            case REVOKED:
                return Decision.invalid(LICENSE_REVOKED);
            case SUSPENDED:
                return Decision.invalid(LICENSE_SUSPENDED);
            case EXPIRED:
                return Decision.invalid(LICENSE_EXPIRED);
            case CREATED:
                return Decision.invalid(LICENSE_INACTIVE);
            case ACTIVE:
                break;
            default:
                return Decision.invalid(LICENSE_INVALID);
        }
        if (!snapshot.signatureValid()) {
            return Decision.invalid(LICENSE_INVALID);
        }
        if (snapshot.nbfEpochSecond() != null && nowEpochSecond < snapshot.nbfEpochSecond()) {
            return Decision.invalid(LICENSE_NOT_YET_VALID);
        }
        if (snapshot.expEpochSecond() != null && nowEpochSecond >= snapshot.expEpochSecond()) {
            return Decision.invalid(LICENSE_EXPIRED);
        }
        return Decision.ok();
    }

    /** {@code grantmint.validation.total}'s {@code result} tag for an unknown/foreign key id. */
    private static final String RESULT_NOT_FOUND = "not_found";

    /**
     * Map a wire reason code to the metric catalog's {@code result} tag vocabulary
     * (MONITORING_LOGGING.md): a closed enum, safe as a Prometheus dimension.
     */
    private static String metricResult(String code) {
        return switch (code) {
            case LICENSE_REVOKED -> "revoked";
            case LICENSE_SUSPENDED -> "suspended";
            case LICENSE_EXPIRED -> "expired";
            case LICENSE_NOT_YET_VALID -> "not_yet_valid";
            case LICENSE_INACTIVE -> "inactive";
            default -> "signature_mismatch";
        };
    }

    private static String messageFor(String code, String keyId, ValidationSnapshot snapshot) {
        return switch (code) {
            case LICENSE_REVOKED -> "License " + keyId + " has been revoked and is no longer valid.";
            case LICENSE_SUSPENDED -> "License " + keyId + " is suspended.";
            case LICENSE_EXPIRED -> "License " + keyId + " has expired.";
            case LICENSE_NOT_YET_VALID -> "License " + keyId + " is not yet valid.";
            case LICENSE_INACTIVE -> "License " + keyId + " has not been activated.";
            default -> "License " + keyId + " failed verification.";
        };
    }

    /** Outcome of {@link #decide}: valid, or invalid with a stable reason code. */
    record Decision(boolean valid, String code) {

        static Decision ok() {
            return new Decision(true, null);
        }

        static Decision invalid(String code) {
            return new Decision(false, code);
        }
    }
}
