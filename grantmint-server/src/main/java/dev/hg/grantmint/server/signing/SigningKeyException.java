package dev.hg.grantmint.server.signing;

/**
 * Raised when signing-key material cannot be resolved or does not match its registered public key.
 *
 * <p>Messages never carry private key bytes — only the reference (scheme + locator) and the nature
 * of the failure, so a stack trace or log line can never leak the seed. 🔒
 */
public class SigningKeyException extends RuntimeException {

    public SigningKeyException(String message) {
        super(message);
    }

    public SigningKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
