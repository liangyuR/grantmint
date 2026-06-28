package dev.hg.grantmint.server.security;

import org.springframework.stereotype.Component;

/**
 * Mints namespaced API-key plaintext and derives its at-rest representation.
 *
 * <p>The namespace prefix makes a key greppable by secret scanners and impossible to misuse across
 * surfaces: a {@code gm_val_…} validation key cannot be presented as a {@code gm_live_…} issuance
 * key because the filters match on the distinct namespace. The secret body is 256 bits of
 * randomness; the key is hashed with SHA-256 for storage and a leading slice is kept for display.
 *
 * <p>See docs/features/ADMIN_AND_API_AUTH.md (Format, Key storage and rotation).
 */
@Component
public class ApiKeyGenerator {

    /** Number of leading characters of the plaintext kept for human display (namespace + a peek). */
    static final int PREFIX_LENGTH = 12;

    /**
     * Mint a key for the given scope and environment. The environment is only meaningful for
     * {@link ApiKeyScope#ISSUANCE}; validation and admin keys ignore it.
     */
    public GeneratedApiKey generate(ApiKeyScope scope, ApiKeyEnvironment environment) {
        String plaintext = namespace(scope, environment) + Secrets.randomTokenHex();
        String keyHash = Secrets.sha256Hex(plaintext);
        String keyPrefix = plaintext.substring(0, Math.min(PREFIX_LENGTH, plaintext.length()));
        return new GeneratedApiKey(plaintext, keyHash, keyPrefix);
    }

    /** The {@code gm_…_} namespace a plaintext key of this scope/environment carries. */
    static String namespace(ApiKeyScope scope, ApiKeyEnvironment environment) {
        return switch (scope) {
            case ISSUANCE -> "gm_" + (environment == null ? ApiKeyEnvironment.LIVE : environment).token() + "_";
            case VALIDATION -> "gm_val_";
            case ADMIN -> "gm_admin_";
        };
    }
}
