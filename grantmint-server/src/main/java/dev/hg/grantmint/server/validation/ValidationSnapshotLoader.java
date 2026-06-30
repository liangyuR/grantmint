package dev.hg.grantmint.server.validation;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.time.Clock;
import dev.hg.grantmint.core.token.FailureReason;
import dev.hg.grantmint.core.token.LicenseVerifier;
import dev.hg.grantmint.core.token.MalformedTokenException;
import dev.hg.grantmint.core.token.SignedToken;
import dev.hg.grantmint.core.token.TokenCodec;
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
 *
 * <p>The token's {@code nbf} (not-before) claim has no database column — it lives only in the signed
 * token — so it is decoded from the (now signature-verified) payload and carried in the snapshot.
 * This keeps the online path at least as strict as the offline verifier: a future-dated token is
 * rejected as {@code not_yet_valid} online too, not silently admitted. {@code exp} continues to come
 * from the {@code expires_at} column (written from the same value at issuance).
 */
@Component
public class ValidationSnapshotLoader {

    private final LicenseRepository licenses;
    private final SigningKeyService signingKeys;
    private final Clock clock;

    public ValidationSnapshotLoader(LicenseRepository licenses, SigningKeyService signingKeys, java.time.Clock clock) {
        this.licenses = licenses;
        this.signingKeys = signingKeys;
        // Adapt the app's java.time.Clock bean to the core Clock abstraction the verifier expects, so
        // a fixed clock in tests propagates here too (rather than hardcoding Clock.system()).
        this.clock = clock::instant;
    }

    /**
     * @throws NoSuchElementException if no license has this key id (rendered as 404; not cached)
     */
    @Transactional(readOnly = true)
    public ValidationSnapshot load(String keyId) {
        License license = licenses.findByKeyIdWithProduct(keyId)
                .orElseThrow(() -> new NoSuchElementException("License not found: " + keyId));
        TokenFacts token = inspectToken(license);
        Long exp =
                license.getExpiresAt() == null ? null : license.getExpiresAt().toEpochSecond();
        return new ValidationSnapshot(
                license.getProduct().getId(),
                license.getStatus(),
                token.signatureValid(),
                token.nbfEpochSecond(),
                exp,
                license.getMaxSeats(),
                license.getEntitlements());
    }

    /**
     * Verify the stored token's signature and, when sound, extract its {@code nbf}. The signature is
     * authentic when the verifier accepts it outright or rejects it only for being expired or
     * not-yet-valid (time, not integrity). A missing/undecodable signing key, or a forged/malformed
     * token, is signature-invalid — and its claims are not trusted, so {@code nbf} stays absent.
     */
    private TokenFacts inspectToken(License license) {
        PublicKey publicKey;
        try {
            // A missing signing key (NoSuchElementException) or a non-point public key both land here.
            publicKey = Ed25519Keys.decodePublicKey(signingKeys.rawPublicKey(license.getSigningKeyId()));
        } catch (RuntimeException missingOrBadKey) {
            return TokenFacts.UNVERIFIABLE;
        }
        String token = license.getSignedToken();
        VerificationResult result = LicenseVerifier.verifyAt(token, publicKey, clock);
        boolean signatureValid = result.valid()
                || result.reason() == FailureReason.EXPIRED
                || result.reason() == FailureReason.NOT_YET_VALID;
        if (!signatureValid) {
            return TokenFacts.UNVERIFIABLE;
        }
        return new TokenFacts(true, notBeforeOf(token));
    }

    /**
     * The {@code nbf} claim of a token whose signature is already verified. Decoding stays total: a
     * malformed payload (which a verified signature should preclude) yields no not-before rather than
     * throwing on the hot path.
     */
    private static Long notBeforeOf(String token) {
        try {
            return TokenCodec.decodePayload(SignedToken.parse(token).payloadSegment())
                    .nbf();
        } catch (MalformedTokenException | IllegalArgumentException | ArithmeticException malformed) {
            return null;
        }
    }

    /** What the stored token tells us beyond the database row: is its signature sound, and its nbf. */
    private record TokenFacts(boolean signatureValid, Long nbfEpochSecond) {
        static final TokenFacts UNVERIFIABLE = new TokenFacts(false, null);
    }
}
