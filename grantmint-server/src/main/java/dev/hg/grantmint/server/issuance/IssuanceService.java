package dev.hg.grantmint.server.issuance;

import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.entitlement.EntitlementSet;
import dev.hg.grantmint.core.keyid.KeyId;
import dev.hg.grantmint.core.token.Holder;
import dev.hg.grantmint.core.token.LicenseTokenIssuer;
import dev.hg.grantmint.core.token.TokenPayload;
import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.PolicyRepository;
import dev.hg.grantmint.server.signing.SigningKeyService;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The mint. Resolves a policy, computes expiry, allocates the short key id, delegates to {@code
 * grantmint-core} to build and sign the token, persists the {@link License}, and emits an audit
 * event — the server-side issuance flow of docs/architecture/ARCHITECTURE.md.
 *
 * <p>Two correctness rails sit here:
 *
 * <ul>
 *   <li><b>Cross-product isolation.</b> The policy must belong to the product the issuance key is
 *       scoped to, or issuance is denied (403) — a {@code prod_a} key can never mint a {@code prod_b}
 *       license. See docs/features/ADMIN_AND_API_AUTH.md.
 *   <li><b>Entitlement snapshot.</b> The policy's entitlements and constraints are copied into the
 *       license <em>and</em> embedded in the signed token at issuance time, so a later policy edit
 *       never mutates an already-issued license.
 * </ul>
 */
@Service
public class IssuanceService {

    /** Bound on key-id allocation retries; collisions are astronomically unlikely (~54 bits). */
    private static final int MAX_KEY_ID_ATTEMPTS = 10;

    private final PolicyRepository policies;
    private final LicenseRepository licenses;
    private final SigningKeyService signingKeys;
    private final AuditService audit;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public IssuanceService(
            PolicyRepository policies,
            LicenseRepository licenses,
            SigningKeyService signingKeys,
            AuditService audit,
            Clock clock) {
        this.policies = policies;
        this.licenses = licenses;
        this.signingKeys = signingKeys;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * Mint a license from a policy.
     *
     * @throws NoSuchElementException if the policy does not exist (mapped to 404)
     * @throws AccessDeniedException if the policy belongs to a different product than the key's scope
     *     (mapped to 403)
     * @throws IllegalArgumentException for a missing holder (mapped to 400)
     */
    @Transactional
    public IssuedLicense issue(IssuanceCommand command) {
        return issue(command, AuditActorType.API_KEY);
    }

    /**
     * Variant with explicit audit attribution — the webhook layer mints with
     * {@code AuditActorType.WEBHOOK} so the trail distinguishes provider-driven issuance from a
     * backend's API key.
     */
    @Transactional
    public IssuedLicense issue(IssuanceCommand command, AuditActorType actorType) {
        if (command.holderName() == null || command.holderName().isBlank()) {
            throw new IllegalArgumentException("holder name is required");
        }
        if (command.holderEmail() == null || command.holderEmail().isBlank()) {
            throw new IllegalArgumentException("holder email is required");
        }
        Policy policy = policies.findById(command.policyId())
                .orElseThrow(() -> new NoSuchElementException("Policy not found: " + command.policyId()));
        Product product = policy.getProduct();
        if (!product.getId().equals(command.productId())) {
            // Real key, wrong product — denied, never a 404 that would leak the policy's existence.
            throw new AccessDeniedException("Issuance key is not scoped to this policy's product");
        }

        Ed25519Signer signer = signingKeys.signerForProduct(product.getId());
        LicenseTokenIssuer issuer = new LicenseTokenIssuer(signer);

        Instant now = clock.instant();
        OffsetDateTime expiresAt = computeExpiry(policy, command.expiresAtOverride(), now);
        // The token's cryptographic exp deliberately trails the database expiry by the policy's
        // grace period: online checks flip at expires_at, while the offline artefact keeps
        // verifying through the grace window (LICENSE_LIFECYCLE.md, "Expiry and grace periods").
        // A trial needs nothing extra — it is a short-duration policy, so its deadline
        // self-enforces offline through this same exp.
        OffsetDateTime tokenExp = expiresAt == null ? null : expiresAt.plusDays(policy.getGracePeriodDays());
        int seatLimit = command.seatOverride() != null ? command.seatOverride() : policy.getMaxSeats();

        Map<String, Object> entitlementSnapshot = copyOf(policy.getEntitlements());
        Map<String, Object> constraintSnapshot = copyOf(policy.getConstraints());

        License license = new License();
        license.setProduct(product);
        license.setPolicy(policy);
        license.setKeyId(allocateKeyId());
        license.setStatus(LicenseStatus.ACTIVE);
        license.setHolderName(command.holderName());
        license.setHolderEmail(command.holderEmail());
        license.setEntitlements(entitlementSnapshot);
        license.setConstraints(constraintSnapshot);
        license.setMaxSeats(seatLimit);
        license.setExpiresAt(expiresAt);
        license.setExternalRef(command.externalRef());

        TokenPayload payload = new TokenPayload(
                TokenPayload.CURRENT_VERSION,
                license.getId().toString(),
                license.getKeyId(),
                product.getSlug(),
                policy.getCode(),
                new Holder(command.holderName(), command.holderEmail()),
                now.getEpochSecond(),
                null,
                tokenExp == null ? null : tokenExp.toEpochSecond(),
                EntitlementSet.decode(entitlementSnapshot),
                constraintSnapshot,
                seatLimit);
        license.setSignedToken(issuer.sign(payload));
        license.setSigningKeyId(signer.signingKeyId());

        licenses.save(license);

        audit.record(
                command.actor(),
                actorType,
                "license.issued",
                "license",
                license.getId().toString(),
                Map.of(
                        "key_id", license.getKeyId(),
                        "policy_id", policy.getId().toString(),
                        "product_id", product.getId().toString()),
                command.ipAddress());

        return new IssuedLicense(license.getKeyId(), license.getSignedToken(), license.getStatus(), expiresAt);
    }

    /** Expiry: an explicit override wins; else policy duration from now; else perpetual (null). */
    private OffsetDateTime computeExpiry(Policy policy, OffsetDateTime override, Instant now) {
        if (override != null) {
            return override;
        }
        Integer durationDays = policy.getDurationDays();
        if (durationDays == null) {
            return null;
        }
        return OffsetDateTime.ofInstant(now, ZoneOffset.UTC).plusDays(durationDays);
    }

    private String allocateKeyId() {
        for (int attempt = 0; attempt < MAX_KEY_ID_ATTEMPTS; attempt++) {
            String keyId = KeyId.generate(random);
            if (!licenses.existsByKeyId(keyId)) {
                return keyId;
            }
        }
        throw new IllegalStateException("Unable to allocate a unique license key id after retries");
    }

    private static Map<String, Object> copyOf(Map<String, Object> source) {
        return source == null ? new LinkedHashMap<>() : new LinkedHashMap<>(source);
    }
}
