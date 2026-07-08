package dev.hg.grantmint.server.security;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Cross-origin policy for the public HTTP surface. The default is DELIBERATELY empty: no CORS
 * headers are emitted at all, browsers enforce same-origin, and the dashboard must be served from
 * the same origin as the API (the dev proxy / same-host deployment). An operator hosting the
 * dashboard elsewhere lists that origin here explicitly; because the dashboard authenticates with
 * a session cookie, allowed origins are always exact matches — a wildcard is never accepted with
 * credentials. Before this property existed the same posture held only by omission; this makes it
 * a declared, testable policy (2026-07 audit, GRANTMINT-168).
 *
 * @param allowedOrigins exact origins ({@code scheme://host[:port]}) allowed to make credentialed
 *     cross-origin requests; empty (the default) disables CORS processing entirely
 */
@ConfigurationProperties(prefix = "grantmint.security.cors")
public record GrantmintCorsProperties(@DefaultValue List<String> allowedOrigins) {}
