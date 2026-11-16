package dev.hg.grantmint.server.activation;

import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.domain.MachineActivation;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.MachineActivationRepository;
import dev.hg.grantmint.server.validation.LicenseNotValidException;
import dev.hg.grantmint.server.validation.ValidationCache;
import dev.hg.grantmint.server.validation.ValidationService;
import dev.hg.grantmint.server.validation.ValidationSnapshot;
import dev.hg.grantmint.server.validation.ValidationSnapshotLoader;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Node-locked device activation and seat enforcement — the online layer a signed token cannot
 * provide. See docs/features/ACTIVATION_AND_SEATS.md.
 *
 * <p><b>The seat invariant.</b> {@code count(activations where status='active') <= license.maxSeats},
 * always. It is enforced in application logic inside the {@link #activate} transaction: the license
 * row is taken with a pessimistic write lock ({@code SELECT … FOR UPDATE}) <em>before</em> the active
 * seats are counted, so two concurrent activations racing for the last free seat serialize on the row
 * lock and exactly one wins. There is no declarative database constraint for the limit — the lock is
 * the whole mechanism, which is why every seat-affecting path here must lock first.
 *
 * <p><b>Idempotent re-activation.</b> {@code UNIQUE(license_id, fingerprint)} guarantees at most one
 * activation row per device. Re-activating a currently-active fingerprint consumes no new seat and
 * succeeds even at the limit (clients may safely call activate on every launch); re-activating a
 * deactivated fingerprint flips the existing row back to {@code active} — subject to the seat check —
 * rather than inserting a second row the unique constraint would reject.
 *
 * <p><b>Lifecycle.</b> The first successful activation is the license's "first online contact": a
 * {@code CREATED} license transitions to {@code ACTIVE} (see docs/features/LICENSE_LIFECYCLE.md).
 * Every seat-affecting change evicts the license's validation-cache entry after commit, so online
 * validation converges immediately instead of waiting out the TTL.
 */
@Service
public class ActivationService {

    /** Wire value of a seat-consuming activation row. */
    public static final String MACHINE_ACTIVE = "active";
    /** Wire value of an explicitly released activation row. */
    public static final String MACHINE_DEACTIVATED = "deactivated";

    /** Fingerprints are opaque but bounded — anything longer is abuse, not a device id. */
    static final int MAX_FINGERPRINT_LENGTH = 256;

    private final LicenseRepository licenses;
    private final MachineActivationRepository activations;
    private final ValidationSnapshotLoader snapshotLoader;
    private final ValidationCache cache;
    private final AuditService audit;
    private final Clock clock;

    public ActivationService(
            LicenseRepository licenses,
            MachineActivationRepository activations,
            ValidationSnapshotLoader snapshotLoader,
            ValidationCache cache,
            AuditService audit,
            Clock clock) {
        this.licenses = licenses;
        this.activations = activations;
        this.snapshotLoader = snapshotLoader;
        this.cache = cache;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * Claim (or idempotently re-claim) a seat for a device.
     *
     * @throws NoSuchElementException if no such license is visible to the requesting product (404)
     * @throws LicenseNotValidException if the license cannot be activated — revoked, suspended,
     *     expired, not yet valid, or carrying a token that fails verification (422)
     * @throws SeatLimitExceededException if all seats are held by other fingerprints (409)
     */
    @Transactional
    public ActivationResult activate(ActivationCommand command) {
        String fingerprint = requireFingerprint(command.fingerprint());
        License license = lockedLicense(command.keyId(), command.requesterProductId());
        assertActivatable(license);

        OffsetDateTime now = now();
        int heartbeatInterval = license.getPolicy().getHeartbeatIntervalSeconds();
        Optional<MachineActivation> existing = activations.findByLicense_IdAndFingerprint(license.getId(), fingerprint);

        if (existing.isPresent() && MACHINE_ACTIVE.equals(existing.get().getStatus())) {
            // Idempotent path: the device already holds a seat. Never fails at the limit, never
            // consumes a second seat — this is what lets clients activate on every launch.
            MachineActivation activation = existing.get();
            activation.setLastHeartbeatAt(now);
            activation.setIpAddress(AuditService.normalizeIpOrNull(command.ipAddress()));
            long seatsUsed = activations.countActiveByLicenseId(license.getId());
            return result(license, activation, seatsUsed, true, heartbeatInterval, now);
        }

        // New fingerprint, or a deactivated row coming back: both need a free seat. The license row
        // is locked, so this count cannot race another activation.
        long seatsUsed = activations.countActiveByLicenseId(license.getId());
        if (seatsUsed >= license.getMaxSeats()) {
            throw new SeatLimitExceededException(command.keyId(), seatsUsed, license.getMaxSeats());
        }

        MachineActivation activation = existing.orElseGet(() -> {
            MachineActivation fresh = new MachineActivation();
            fresh.setLicense(license);
            fresh.setFingerprint(fingerprint);
            return fresh;
        });
        activation.setStatus(MACHINE_ACTIVE);
        activation.setDeactivatedAt(null);
        activation.setLastHeartbeatAt(now);
        activation.setIpAddress(AuditService.normalizeIpOrNull(command.ipAddress()));
        if (command.machineName() != null) {
            activation.setMachineName(command.machineName());
        }
        if (command.platform() != null) {
            activation.setPlatform(command.platform());
        }
        if (command.metadata() != null && !command.metadata().isEmpty()) {
            activation.setMetadata(new HashMap<>(command.metadata()));
        }
        // Flush so @CreationTimestamp/@GeneratedValue are populated on the returned view.
        activation = activations.saveAndFlush(activation);

        if (license.getStatus() == LicenseStatus.CREATED) {
            // First online contact: CREATED -> ACTIVE (docs/features/LICENSE_LIFECYCLE.md).
            license.setStatus(LicenseStatus.ACTIVE);
            license.setActivatedAt(now);
            licenses.save(license);
        }

        audit.record(
                command.actor(),
                AuditActorType.API_KEY,
                "activation.created",
                "license",
                license.getId().toString(),
                Map.of(
                        "key_id",
                        license.getKeyId(),
                        "fingerprint",
                        fingerprint,
                        "seats_used",
                        seatsUsed + 1,
                        "seats_total",
                        license.getMaxSeats()),
                command.ipAddress());
        evictAfterCommit(license.getKeyId());
        return result(license, activation, seatsUsed + 1, false, heartbeatInterval, now);
    }

    /**
     * Release the seat held by a fingerprint. Deliberately not gated on license health — freeing a
     * seat on a revoked or expired license is always harmless and always allowed.
     *
     * @throws NoSuchElementException if no such license is visible to the requesting product (404)
     * @throws ActivationNotFoundException if the fingerprint holds no active seat (404); repeating a
     *     deactivate is safe — the seat count is untouched and never goes negative
     */
    @Transactional
    public DeactivationResult deactivate(
            String keyId, UUID requesterProductId, String rawFingerprint, String actor, String ipAddress) {
        String fingerprint = requireFingerprint(rawFingerprint);
        // Locked for the same reason as activate: the freed-seat count below must serialize with any
        // concurrent activation's seat check.
        License license = lockedLicense(keyId, requesterProductId);

        MachineActivation activation = activations
                .findByLicense_IdAndFingerprint(license.getId(), fingerprint)
                .filter(a -> MACHINE_ACTIVE.equals(a.getStatus()))
                .orElseThrow(() -> new ActivationNotFoundException(keyId, fingerprint));

        OffsetDateTime now = now();
        activation.setStatus(MACHINE_DEACTIVATED);
        activation.setDeactivatedAt(now);
        long seatsUsed = activations.countActiveByLicenseId(license.getId());

        audit.record(
                actor,
                AuditActorType.API_KEY,
                "activation.deactivated",
                "license",
                license.getId().toString(),
                Map.of(
                        "key_id",
                        license.getKeyId(),
                        "fingerprint",
                        fingerprint,
                        "seats_used",
                        seatsUsed,
                        "seats_total",
                        license.getMaxSeats()),
                ipAddress);
        evictAfterCommit(license.getKeyId());
        return new DeactivationResult(keyId, fingerprint, seatsUsed, license.getMaxSeats(), now);
    }

    /**
     * Refresh a device's {@code last_heartbeat_at}, keeping its seat from the timeout reaper (M7).
     * This is also the moment a previously-offline device learns its license was revoked or
     * suspended, so the license-health gate runs before the touch.
     *
     * @throws NoSuchElementException if no such license is visible to the requesting product (404)
     * @throws LicenseNotValidException if the license is revoked/suspended/expired/inactive (422)
     * @throws ActivationNotFoundException if the fingerprint holds no active seat (404) — the client
     *     should re-activate
     */
    @Transactional
    public HeartbeatResult heartbeat(String keyId, UUID requesterProductId, String rawFingerprint) {
        String fingerprint = requireFingerprint(rawFingerprint);
        // No row lock: touching a heartbeat neither consumes nor frees a seat.
        License license = licenses.findByKeyId(keyId)
                .orElseThrow(() -> new NoSuchElementException("License not found: " + keyId));
        guardProduct(license, requesterProductId, keyId);
        if (license.isOfflineDevice())
            throw new dev.hg.grantmint.server.offline.OfflineLicenseException(409, "offline_requires_v2");
        assertHeartbeatable(license);

        MachineActivation activation = activations
                .findByLicense_IdAndFingerprint(license.getId(), fingerprint)
                .filter(a -> MACHINE_ACTIVE.equals(a.getStatus()))
                .orElseThrow(() -> new ActivationNotFoundException(keyId, fingerprint));

        OffsetDateTime now = now();
        activation.setLastHeartbeatAt(now);
        int heartbeatInterval = license.getPolicy().getHeartbeatIntervalSeconds();
        return new HeartbeatResult(
                keyId,
                fingerprint,
                license.getStatus().wire(),
                MACHINE_ACTIVE,
                now,
                now.plusSeconds(heartbeatInterval));
    }

    /**
     * Admin-only: free a seat regardless of which device holds it (e.g. "customer lost a laptop").
     * Unlike {@link #deactivate}, this is addressed by activation id rather than fingerprint and
     * carries no fingerprint ownership check — the caller is an operator, not the device. Takes the
     * same license row lock as {@link #activate} so it serializes with a concurrent activation racing
     * for the freed seat.
     *
     * @throws NoSuchElementException if no such license is visible (404), or {@code activationId} does
     *     not exist, does not belong to this license, or does not currently hold an active seat (404)
     */
    @Transactional
    public void forceDeactivate(UUID activationId, String keyId, String actor) {
        License license = lockedLicense(keyId, null);
        MachineActivation activation = activations
                .findById(activationId)
                .filter(a -> license.getId().equals(a.getLicense().getId()))
                .filter(a -> MACHINE_ACTIVE.equals(a.getStatus()))
                .orElseThrow(() -> new NoSuchElementException("Active activation not found: " + activationId));

        OffsetDateTime now = now();
        activation.setStatus(MACHINE_DEACTIVATED);
        activation.setDeactivatedAt(now);

        audit.record(
                actor,
                AuditActorType.ADMIN,
                "activation.deactivated",
                "license",
                license.getId().toString(),
                Map.of(
                        "key_id",
                        license.getKeyId(),
                        "fingerprint",
                        activation.getFingerprint(),
                        "activation_id",
                        activationId.toString()),
                null);
        evictAfterCommit(license.getKeyId());
    }

    /** Lock the license row and enforce cross-product isolation (a foreign key id 404s, never leaks). */
    private License lockedLicense(String keyId, UUID requesterProductId) {
        License license = licenses.findByKeyIdForUpdate(keyId)
                .orElseThrow(() -> new NoSuchElementException("License not found: " + keyId));
        guardProduct(license, requesterProductId, keyId);
        if (license.isOfflineDevice())
            throw new dev.hg.grantmint.server.offline.OfflineLicenseException(409, "offline_requires_v2");
        return license;
    }

    private static void guardProduct(License license, UUID requesterProductId, String keyId) {
        if (requesterProductId != null
                && !requesterProductId.equals(license.getProduct().getId())) {
            throw new NoSuchElementException("License not found: " + keyId);
        }
    }

    /**
     * Activation gate: database status first (revoked/suspended/expired), then the stored token —
     * signature and {@code nbf} — so activation stays exactly as strict as online validation. Unlike
     * validation, {@code CREATED} is welcome here: activating is precisely how it becomes ACTIVE.
     */
    private void assertActivatable(License license) {
        switch (license.getStatus()) {
            case REVOKED -> throw notValid(ValidationService.LICENSE_REVOKED, license);
            case SUSPENDED -> throw notValid(ValidationService.LICENSE_SUSPENDED, license);
            case EXPIRED -> throw notValid(ValidationService.LICENSE_EXPIRED, license);
            case CREATED, ACTIVE -> {
                // usable — fall through to the temporal + token checks
            }
        }
        long nowEpoch = clock.instant().getEpochSecond();
        if (license.getExpiresAt() != null && nowEpoch >= license.getExpiresAt().toEpochSecond()) {
            throw notValid(ValidationService.LICENSE_EXPIRED, license);
        }
        // Fresh (uncached) token facts; joins this transaction, so it reads the locked row.
        ValidationSnapshot snapshot = snapshotLoader.load(license.getKeyId());
        if (!snapshot.signatureValid()) {
            throw notValid(ValidationService.LICENSE_INVALID, license);
        }
        if (snapshot.nbfEpochSecond() != null && nowEpoch < snapshot.nbfEpochSecond()) {
            throw notValid(ValidationService.LICENSE_NOT_YET_VALID, license);
        }
    }

    /** Heartbeat gate: like activation but CREATED is inactive here — a seat implies a prior activate. */
    private void assertHeartbeatable(License license) {
        switch (license.getStatus()) {
            case REVOKED -> throw notValid(ValidationService.LICENSE_REVOKED, license);
            case SUSPENDED -> throw notValid(ValidationService.LICENSE_SUSPENDED, license);
            case EXPIRED -> throw notValid(ValidationService.LICENSE_EXPIRED, license);
            case CREATED -> throw notValid(ValidationService.LICENSE_INACTIVE, license);
            case ACTIVE -> {
                // usable — fall through to the temporal check
            }
        }
        if (license.getExpiresAt() != null
                && clock.instant().getEpochSecond() >= license.getExpiresAt().toEpochSecond()) {
            throw notValid(ValidationService.LICENSE_EXPIRED, license);
        }
    }

    private static LicenseNotValidException notValid(String code, License license) {
        String keyId = license.getKeyId();
        String message =
                switch (code) {
                    case ValidationService.LICENSE_REVOKED -> "License " + keyId
                            + " has been revoked and is no longer valid.";
                    case ValidationService.LICENSE_SUSPENDED -> "License " + keyId + " is suspended.";
                    case ValidationService.LICENSE_EXPIRED -> "License " + keyId + " has expired.";
                    case ValidationService.LICENSE_NOT_YET_VALID -> "License " + keyId + " is not yet valid.";
                    case ValidationService.LICENSE_INACTIVE -> "License " + keyId + " has not been activated.";
                    default -> "License " + keyId + " failed verification.";
                };
        return new LicenseNotValidException(code, message);
    }

    private static String requireFingerprint(String fingerprint) {
        if (fingerprint == null || fingerprint.isBlank()) {
            throw new IllegalArgumentException("fingerprint is required");
        }
        String trimmed = fingerprint.strip();
        if (trimmed.length() > MAX_FINGERPRINT_LENGTH) {
            throw new IllegalArgumentException("fingerprint exceeds " + MAX_FINGERPRINT_LENGTH + " characters");
        }
        return trimmed;
    }

    private ActivationResult result(
            License license,
            MachineActivation activation,
            long seatsUsed,
            boolean reactivated,
            int heartbeatIntervalSeconds,
            OffsetDateTime now) {
        return new ActivationResult(
                license.getKeyId(),
                activation.getId(),
                activation.getFingerprint(),
                MACHINE_ACTIVE,
                reactivated,
                seatsUsed,
                license.getMaxSeats(),
                activation.getActivatedAt() == null ? now : activation.getActivatedAt(),
                heartbeatIntervalSeconds,
                now.plusSeconds(heartbeatIntervalSeconds));
    }

    private OffsetDateTime now() {
        return OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
    }

    /**
     * Evict the validation-cache entry only after the transaction commits. Evicting inline would let
     * a concurrent validate re-populate the cache from the pre-commit row and pin stale state for a
     * full TTL; after commit, the next load sees the new truth.
     */
    private void evictAfterCommit(String keyId) {
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                cache.evict(keyId);
            }
        });
    }
}
