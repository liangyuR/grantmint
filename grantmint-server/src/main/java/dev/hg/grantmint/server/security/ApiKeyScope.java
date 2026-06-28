package dev.hg.grantmint.server.security;

import java.util.List;
import java.util.Locale;

/**
 * The capability tier of an API key, matching the {@code ck_api_keys_scope} CHECK constraint and
 * the three auth schemes in docs/features/ADMIN_AND_API_AUTH.md.
 *
 * <p>Read top-to-bottom as a privilege gradient — {@link #ADMIN} &gt; {@link #ISSUANCE} &gt;
 * {@link #VALIDATION} — where each lower tier can do strictly less than the one above and a
 * compromise of a lower tier cannot escalate.
 */
public enum ApiKeyScope {

    /** Mint and revoke licenses for one product (Scheme 2): {@code SCOPE_ISSUE} + {@code SCOPE_REVOKE}. */
    ISSUANCE(List.of("SCOPE_ISSUE", "SCOPE_REVOKE")),

    /** Validate/activate/heartbeat for one product (Scheme 3): {@code SCOPE_VALIDATION}. */
    VALIDATION(List.of("SCOPE_VALIDATION")),

    /** Reserved for global admin API keys; primary admin auth is the session scheme (Scheme 1). */
    ADMIN(List.of("ROLE_ADMIN"));

    private final List<String> authorities;

    ApiKeyScope(List<String> authorities) {
        this.authorities = authorities;
    }

    /** The Spring Security granted authorities a key of this scope confers. */
    public List<String> authorities() {
        return authorities;
    }

    /** The lowercase token stored in {@code api_keys.scope}. */
    public String wire() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** Parse the persisted {@code api_keys.scope} token back to an enum, {@link Locale#ROOT}-safe. */
    public static ApiKeyScope fromWire(String wire) {
        return ApiKeyScope.valueOf(wire.toUpperCase(Locale.ROOT));
    }
}
