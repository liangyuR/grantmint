package dev.hg.grantmint.server.validation;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.time.Clock;
import dev.hg.grantmint.core.token.FailureReason;
import dev.hg.grantmint.core.token.LicenseVerifier;
import dev.hg.grantmint.core.token.VerificationResult;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.signing.SigningKeyService;
import java.security.PublicKey;
import java.util.NoSuchElementException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Builds a {@link ValidationSnapshot} from the database on a cache miss. Isolated into its own bean
 * so its {@code @Transactional} boundary is honoured through the Spring proxy (a cache loader invoked
 * from {@link ValidationService} would otherwise self-invoke and skip the transaction).
 *
 * <p>The Ed25519 signature is verified here, once, against the stored token using the license's
 * signing-key public half resolved by the token's signing-key id. The verification clock is
 * irrelevant to the cached {@code signatureValid} flag: the offline pipeline checks the signature
 * <em>before</em> {@code nbf}/{@code exp}, so a token that is merely expired or not-yet-valid still
 * has a sound signature. Temporal validity is re-decided per request by {@link ValidationService}.
 */
@Component
public class ValidationSnapshotLoader {

    private final LicenseRepository licenses;
    private final SigningKeyService signingKeys;

    public ValidationSnapshotLoader(LicenseRepository licenses, SigningKeyService signingKeys) {
        this.licenses = licenses;
        this.signingKeys = signingKeys;
    }

    /**
     * @throws NoSuchElementException if no license has this key id (rendered as 404; not cached)
     */
    @Transactional(readOnly = true)
    public ValidationSnapshot load(String keyId) {
        License license = licenses.findByKeyId(keyId)
                .orElseThrow(() -> new NoSuchElementException("License not found: " + keyId));
        Long exp =
                license.getExpiresAt() == null ? null : license.getExpiresAt().toEpochSecond();
        return new ValidationSnapshot(
                license.getProduct().getId(),
                license.getStatus(),
                verifySignature(license),
                null,
                exp,
                license.getMaxSeats(),
                license.getEntitlements());
    }

    /**
     * True when the stored token carries an authentic Ed25519 signature under the registered public
     * key — independent of expiry. A missing or undecodable signing key, or a forged/malformed token,
     * is signature-invalid; an otherwise-sound token that is merely expired or not-yet-valid is not.
     */
    private boolean verifySignature(License license) {
        PublicKey publicKey;
        try {
            // A missing signing key (NoSuchElementException) or a non-point public key both land here.
            publicKey = Ed25519Keys.decodePublicKey(signingKeys.rawPublicKey(license.getSigningKeyId()));
        } catch (RuntimeException missingOrBadKey) {
            return false;
        }
        VerificationResult result = LicenseVerifier.verifyAt(license.getSignedToken(), publicKey, Clock.system());
        return result.valid()
                || result.reason() == FailureReason.EXPIRED
                || result.reason() == FailureReason.NOT_YET_VALID;
    }
}
