package dev.hg.grantmint.core.token;

/**
 * Thrown when a token string is structurally invalid (wrong segment count, undecodable Base64, or
 * non-JSON contents) — distinct from a well-formed token that fails the signature or time checks.
 */
public final class MalformedTokenException extends RuntimeException {

    public MalformedTokenException(String message) {
        super(message);
    }

    public MalformedTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
