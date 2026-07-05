package dev.hg.grantmint.server.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Controls who may reach the OpenAPI document ({@code /v3/api-docs}) and Swagger UI
 * ({@code /swagger-ui}). These endpoints fall outside the three functional auth chains, so without an
 * explicit policy they would be world-readable. The document carries no secrets (only the API shape),
 * but advertising a licensing server's full API surface is not a decision to make by omission — the
 * default is {@link Access#ADMIN} (the hardened posture API_DOCUMENTATION.md promises), and a
 * deployment that wants springdoc-style open docs opts in with {@code public}.
 *
 * <p>Configure via {@code grantmint.openapi.access} = {@code public} | {@code admin} | {@code
 * disabled}. See {@code GrantmintSecurityConfig#openApiDocsChain}.
 */
@ConfigurationProperties("grantmint.openapi")
public class GrantmintOpenApiProperties {

    /** Who may read the OpenAPI doc / Swagger UI. */
    public enum Access {
        /** World-readable — opt-in, convenient for local dev. */
        PUBLIC,
        /** Requires a valid admin session (Scheme 1) — the default. */
        ADMIN,
        /** Not served — every request is rejected. */
        DISABLED
    }

    private Access access = Access.ADMIN;

    public Access getAccess() {
        return access;
    }

    public void setAccess(Access access) {
        this.access = access == null ? Access.ADMIN : access;
    }
}
