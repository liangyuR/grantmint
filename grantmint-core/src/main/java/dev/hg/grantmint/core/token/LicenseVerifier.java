package dev.hg.grantmint.core.token;

import dev.hg.grantmint.core.crypto.Ed25519Verifier;
import dev.hg.grantmint.core.time.Clock;
import java.security.PublicKey;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Offline license-token verification — the product's correctness boundary.
 *
 * <p>A verifier holds one or more embedded Ed25519 public keys, indexed by signing-key id so a
 * single client can validate tokens across a signing-key rotation. {@link #verifyAt} performs the
 * full offline check (structure → algorithm pinning → type pinning → signature → format version →
 * optional product binding → not-before → expiry) and returns a
 * {@link VerificationResult}. No step contacts a network; revocation and seat counting are
 * deliberately absent here (they require the online layer keyed by the license key ID).
 *
 * <p>The signature is checked against the <em>received</em> signing-input bytes, never a
 * re-serialization. See docs/features/LICENSE_TOKEN_FORMAT.md.
 */
public final class LicenseVerifier {

    private final Function<String, PublicKey> keyResolver;

    private LicenseVerifier(Function<String, PublicKey> keyResolver) {
        this.keyResolver = keyResolver;
    }

    /** A verifier holding a single signing key (its id is ignored — this key verifies every token). */
    public static LicenseVerifier of(PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "publicKey");
        return new LicenseVerifier(kid -> publicKey);
    }

    /** A verifier holding public keys indexed by signing-key id (for rotation). */
    public static LicenseVerifier ofKeyring(Map<String, PublicKey> keysBySigningId) {
        Objects.requireNonNull(keysBySigningId, "keysBySigningId");
        Map<String, PublicKey> copy = Map.copyOf(keysBySigningId);
        return new LicenseVerifier(copy::get);
    }

    /**
     * Verify a token offline as of {@code clock}'s current time, without binding it to a product.
     *
     * @return a valid result with the authenticated claims, or a failure with the {@link
     *     FailureReason}
     */
    public VerificationResult verifyAt(String token, Clock clock) {
        return verifyAt(token, clock, null);
    }

    /**
     * Verify a token offline as of {@code clock}'s current time, bound to an expected product.
     *
     * <p>When {@code expectedProductId} is non-null, the authenticated {@code prd} claim must equal it
     * or the result is {@link FailureReason#WRONG_PRODUCT}. This closes the cross-product acceptance
     * gap in a deployment where one Ed25519 key pair signs tokens for several products: a sibling
     * product's authentic token would otherwise verify here. Pass {@code null} to skip the check (the
     * single-product case, where the embedded public key already scopes trust).
     *
     * @return a valid result with the authenticated claims, or a failure with the {@link
     *     FailureReason}
     */
    public VerificationResult verifyAt(String token, Clock clock, String expectedProductId) {
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(clock, "clock");
        return verify(token, keyResolver, clock, expectedProductId);
    }

    /**
     * Static convenience: verify a token against a single public key as of {@code clock}.
     *
     * <p>Mirrors {@code verifyAt(token, pubKey, clock)} from the spec. Performs no product binding.
     */
    public static VerificationResult verifyAt(String token, PublicKey publicKey, Clock clock) {
        return of(publicKey).verifyAt(token, clock, null);
    }

    /**
     * Static convenience: verify a token against a single public key as of {@code clock}, bound to an
     * expected product. See {@link #verifyAt(String, Clock, String)}.
     */
    public static VerificationResult verifyAt(
            String token, PublicKey publicKey, Clock clock, String expectedProductId) {
        return of(publicKey).verifyAt(token, clock, expectedProductId);
    }

    private static VerificationResult verify(
            String token, Function<String, PublicKey> resolver, Clock clock, String expectedProductId) {
        // 1. Structure — segment shape, strict base64url decodability of ALL THREE segments, and a
        // header carrying the required string fields. Every segment is decoded eagerly, before the
        // header gates and the signature, exactly like the starter/Go/Swift/TS verifiers: a
        // corrupt or padded segment is MALFORMED in all five implementations, never FORGED via a
        // signature check that a broken segment had already doomed.
        SignedToken parts;
        TokenHeader header;
        byte[] signature;
        try {
            parts = SignedToken.parse(token);
            header = TokenCodec.decodeHeader(parts.headerSegment());
            parts.payloadBytes();
            signature = parts.signatureBytes();
        } catch (MalformedTokenException | IllegalArgumentException | ArithmeticException e) {
            // Wrong segment count, undecodable base64/JSON, or a header missing required string fields.
            return VerificationResult.failure(FailureReason.MALFORMED);
        }

        // 2. Signature-scheme pinning — reject anything but EdDSA/Ed25519 before touching the signature.
        if (!header.pinsAllowedSignatureScheme()) {
            return VerificationResult.failure(FailureReason.ALG_NOT_ALLOWED);
        }

        // 2b. Token-type pinning — a correctly-signed token with a foreign typ (e.g. a generic JWT) is
        // not a Grantmint license. Checked before the signature, like the scheme pin.
        if (!header.pinsExpectedType()) {
            return VerificationResult.failure(FailureReason.WRONG_TYPE);
        }

        // 3. Signature over the RECEIVED bytes. Unknown key id => forged.
        PublicKey publicKey = resolver.apply(header.kid());
        if (publicKey == null) {
            return VerificationResult.failure(FailureReason.FORGED);
        }
        if (!new Ed25519Verifier(publicKey).verify(parts.signingInput(), signature)) {
            return VerificationResult.failure(FailureReason.FORGED);
        }

        // 4. Claims are now trustworthy — parse them. Any structural, type, or out-of-range claim
        // (e.g. a fractional or oversized integer) is a malformed token, never a thrown exception:
        // verification is a boolean decision. TokenCodec already maps these to MalformedTokenException;
        // the broad catch here is defence-in-depth for the correctness boundary.
        TokenPayload payload;
        try {
            payload = TokenCodec.decodePayload(parts.payloadSegment());
        } catch (MalformedTokenException | IllegalArgumentException | ArithmeticException e) {
            return VerificationResult.failure(FailureReason.MALFORMED);
        }

        // 5. Format-version gate — the claims are authentic, but refuse to interpret a layout this
        // verifier does not understand. Fail-closed: an unknown future version is rejected, never
        // guessed at. (An out-of-int-range ver is already MALFORMED at parse, above.)
        if (payload.ver() != TokenPayload.CURRENT_VERSION) {
            return VerificationResult.failure(FailureReason.UNSUPPORTED_VERSION);
        }

        // 6. Product binding — an authentic token for a sibling product (same signing key pair) must
        // not pass another product's gate. Skipped when the caller expects no specific product.
        if (expectedProductId != null && !expectedProductId.equals(payload.prd())) {
            return VerificationResult.failure(FailureReason.WRONG_PRODUCT);
        }

        // 7. Temporal validity.
        long now = clock.nowEpochSecond();
        if (payload.nbf() != null && now < payload.nbf()) {
            return VerificationResult.failure(FailureReason.NOT_YET_VALID);
        }
        if (payload.exp() != null && now >= payload.exp()) {
            return VerificationResult.failure(FailureReason.EXPIRED);
        }
        return VerificationResult.ok(header, payload);
    }
}
