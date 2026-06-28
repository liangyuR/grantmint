package dev.hg.grantmint.core.keyid;

/**
 * Thrown when a typed/stored key ID cannot be normalized into a valid {@code XXXX-XXXX-XXXX} key ID
 * — wrong length after cleanup, an out-of-alphabet character, or a failed checksum.
 *
 * <p>The original (untrusted) input is preserved in the message so support can see what the customer
 * actually typed; it is the caller's job not to echo it into logs at scale.
 */
public final class InvalidKeyIdException extends RuntimeException {

    public InvalidKeyIdException(String typed) {
        super("Invalid key ID: " + typed);
    }
}
