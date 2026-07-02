package dev.hg.grantmint.client.verify;

/**
 * Offline verification refused the token. The reason distinguishes the cryptographic outcomes a
 * client should treat differently: a malformed or forged token is never acceptable; an expired or
 * not-yet-valid one has a sound signature but sits outside its temporal window.
 */
public class TokenVerificationException extends RuntimeException {

    /** Why verification refused the token. */
    public enum Reason {
        /** Structurally broken: wrong segment count, bad base64url, invalid JSON, missing claims. */
        MALFORMED,
        /** Header pinning failed or the Ed25519 signature does not match the signing input. */
        INVALID_SIGNATURE,
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
