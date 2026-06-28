package dev.hg.grantmint.server.security;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Admin auth configuration (Scheme 1). The bootstrap credentials seed the first operator on an
 * empty {@code admin_users} table; thereafter operators are managed through the API. See
 * docs/features/ADMIN_AND_API_AUTH.md.
 *
 * @param bootstrapUsername username for the bootstrap admin, used only when the table is empty
 * @param bootstrapPassword password for the bootstrap admin; when blank, no bootstrap admin is
 *     created (the operator must seed one another way)
 * @param session session-token settings
 */
@ConfigurationProperties(prefix = "grantmint.admin")
public record GrantmintAdminProperties(
        @DefaultValue("admin") String bootstrapUsername, String bootstrapPassword, @DefaultValue Session session) {

    /**
     * @param ttl absolute lifetime of a freshly minted session token
     * @param cookieName name of the optional browser session cookie
     * @param bearerEnabled whether {@code Authorization: Bearer gm_sess_…} is accepted (for CLI/API)
     */
    public record Session(
            @DefaultValue("8h") Duration ttl,
            @DefaultValue("gm_admin_session") String cookieName,
            @DefaultValue("true") boolean bearerEnabled) {}
}
