package dev.hg.grantmint.core.crypto;

/**
 * Unchecked wrapper for the JCA's checked {@link java.security.GeneralSecurityException} family.
 *
 * <p>Ed25519 is a JDK-built-in algorithm with no provider to misconfigure, so the checked
 * exceptions the JCA declares are, in practice, "this JVM is broken" conditions rather than
 * recoverable errors. Wrapping them keeps the crypto API clean (callers do not litter signing and
 * verification with {@code try/catch} for impossible cases) while still surfacing the cause.
 */
public final class CryptoException extends RuntimeException {

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
