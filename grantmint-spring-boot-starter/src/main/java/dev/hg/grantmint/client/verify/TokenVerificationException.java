package dev.hg.grantmint.client.verify;

/**
 * Offline verification refused the token. The reason distinguishes the cryptographic outcomes a
 * client should treat differently: a malformed or forged token is never acceptable; an expired or
 * not-yet-valid one has a sound signature but sits outside its temporal window.
 */
public class TokenVerificationException extends RuntimeException {

    /**
     * Why verification refused the token. Mirrors the reference verifier's taxonomy one-to-one
     * (grantmint-core {@code FailureReason}) so callers branching on the reason — telemetry telling
     * an algorithm-confusion attempt apart from a corrupt token — see the same classification from
     * either implementation.
     */
    public enum Reason {
        /** Structurally broken: wrong segment count, bad base64url, invalid JSON, missing claims. */
        MALFORMED,
        /** Header declares a signature scheme other than the pinned {@code alg=EdDSA, crv=Ed25519}. */
        ALG_NOT_ALLOWED,
        /** Header declares a foreign token type (e.g. a generic JWT) instead of {@code typ=GMT}. */
        WRONG_TYPE,
        /** The Ed25519 signature does not match the signing input. */
        INVALID_SIGNATURE,
        /** Signature sound, but the claims declare a format version this verifier does not know. */
        UNSUPPORTED_VERSION,
        /** Signature sound, but {@code now >= exp} (exp is exclusive). */
        EXPIRED,
        /** Signature sound, but {@code now < nbf}. */
        NOT_YET_VALID,
        /** Signature sound, but the token's {@code prd} is not the configured product. */
        WRONG_PRODUCT
    }

    private final Reason reason;

    public TokenVerificationException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
