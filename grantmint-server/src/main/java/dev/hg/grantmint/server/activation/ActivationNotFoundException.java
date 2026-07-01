package dev.hg.grantmint.server.activation;

/**
 * The fingerprint holds no active seat on this license — nothing to release or heartbeat. Rendered
 * as a {@code 404 Not Found} with code {@code activation_not_found}. Deactivation stays idempotent in
 * spirit: repeating it hits this instead of corrupting the seat count, which never goes negative.
 */
public class ActivationNotFoundException extends RuntimeException {

    public ActivationNotFoundException(String keyId, String fingerprint) {
        super("No active machine with fingerprint '" + fingerprint + "' on license " + keyId + ".");
    }
}
