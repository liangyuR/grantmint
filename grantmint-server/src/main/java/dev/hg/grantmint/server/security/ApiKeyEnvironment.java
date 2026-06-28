package dev.hg.grantmint.server.security;

import java.util.Locale;

/**
 * Environment tag baked into an issuance key's namespace so a {@code gm_test_…} key can never act
 * on production data and vice-versa. Validation and admin keys are environment-agnostic.
 */
public enum ApiKeyEnvironment {
    LIVE,
    TEST;

    /** The lowercase token used inside the key namespace, e.g. {@code live} in {@code gm_live_…}. */
    public String token() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** Parse a request-supplied environment, {@link Locale#ROOT}-safe; defaults to {@link #LIVE}. */
    public static ApiKeyEnvironment fromToken(String token) {
        if (token == null || token.isBlank()) {
            return LIVE;
        }
        return ApiKeyEnvironment.valueOf(token.trim().toUpperCase(Locale.ROOT));
    }
}
