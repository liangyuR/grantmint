package dev.hg.grantmint.server.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Controls who may reach the OpenAPI document ({@code /v3/api-docs}) and Swagger UI
 * ({@code /swagger-ui}). These endpoints fall outside the three functional auth chains, so without an
 * explicit policy they would be world-readable. The document carries no secrets (only the API shape),
 * so the default is {@link Access#PUBLIC} — springdoc's own default and convenient for local dev — but
 * a deployment that does not want its API surface advertised can lock it down without code changes.
 *
 * <p>Configure via {@code grantmint.openapi.access} = {@code public} | {@code admin} | {@code
 * disabled}. See {@code GrantmintSecurityConfig#openApiDocsChain}.
 */
@ConfigurationProperties("grantmint.openapi")
public class GrantmintOpenApiProperties {

    /** Who may read the OpenAPI doc / Swagger UI. */
    public enum Access {
        /** World-readable (default). */
        PUBLIC,
        /** Requires a valid admin session (Scheme 1). */
        ADMIN,
        /** Not served — every request is rejected. */
        DISABLED
    }

    private Access access = Access.PUBLIC;

    public Access getAccess() {
        return access;
    }

    public void setAccess(Access access) {
        this.access = access == null ? Access.PUBLIC : access;
    }
}
