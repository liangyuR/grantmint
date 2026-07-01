package dev.hg.grantmint.server.security;

import java.time.Clock;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Wires the three independent, path-scoped {@link SecurityFilterChain}s — the code-level expression
 * of blast-radius isolation. Each surface is evaluated by exactly one chain, ordered most-specific
 * first: validation (hottest path) → issuance → admin. Requests outside all three matchers (e.g.
 * actuator health) bypass security entirely. See docs/features/ADMIN_AND_API_AUTH.md.
 *
 * <p>v1 note: all three chains are stateless and CSRF-disabled because authentication is by
 * bearer/header token (and our own server-side session store), not a Spring HTTP session. The
 * browser cookie + CSRF flow lands with the M11 dashboard.
 */
@Configuration
@EnableConfigurationProperties({GrantmintAdminProperties.class, GrantmintOpenApiProperties.class})
public class GrantmintSecurityConfig {

    /** OpenAPI doc + Swagger UI paths (springdoc), gated by {@link GrantmintOpenApiProperties}. */
    private static final String[] OPENAPI_PATHS = {
        "/v3/api-docs", "/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**"
    };

    /**
     * Chain 0 — OPENAPI docs. Most specific so it wins for doc/UI paths before any functional chain.
     * Its policy is configurable because these endpoints sit outside the three auth surfaces: public
     * by default, lockable to admin-only or fully disabled in production.
     */
    @Bean
    @Order(0)
    SecurityFilterChain openApiDocsChain(
            HttpSecurity http,
            GrantmintOpenApiProperties openApi,
            AdminSessionService sessions,
            GrantmintAdminProperties adminProperties,
            SecurityErrorResponder errors)
            throws Exception {
        http.securityMatcher(OPENAPI_PATHS)
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        switch (openApi.getAccess()) {
            case PUBLIC -> http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
            case DISABLED -> http.authorizeHttpRequests(
                            auth -> auth.anyRequest().denyAll())
                    .exceptionHandling(ex -> ex.authenticationEntryPoint(errors).accessDeniedHandler(errors));
            case ADMIN -> http.addFilterBefore(
                            new AdminSessionAuthFilter(sessions, adminProperties),
                            UsernamePasswordAuthenticationFilter.class)
                    .authorizeHttpRequests(auth -> auth.anyRequest().hasRole("ADMIN"))
                    .exceptionHandling(ex -> ex.authenticationEntryPoint(errors).accessDeniedHandler(errors));
        }
        return http.build();
    }

    /** Chain 1 — VALIDATION (most specific, highest precedence, hottest path). */
    @Bean
    @Order(1)
    SecurityFilterChain validationChain(HttpSecurity http, ApiKeyService apiKeys, SecurityErrorResponder errors)
            throws Exception {
        return http.securityMatcher("/v1/licenses/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new ValidationKeyAuthFilter(apiKeys), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth.anyRequest().hasAuthority("SCOPE_VALIDATION"))
                .exceptionHandling(ex -> ex.authenticationEntryPoint(errors).accessDeniedHandler(errors))
                .build();
    }

    /** Chain 2 — ISSUANCE. Backend/CI mints and revokes licenses for one product. */
    @Bean
    @Order(2)
    SecurityFilterChain issuanceChain(HttpSecurity http, ApiKeyService apiKeys, SecurityErrorResponder errors)
            throws Exception {
        return http.securityMatcher("/issuance/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new IssuanceKeyAuthFilter(apiKeys), UsernamePasswordAuthenticationFilter.class)
                // Per-method split: lifecycle mutations (suspend/reinstate/revoke) demand SCOPE_REVOKE,
                // everything else (minting) demands SCOPE_ISSUE. Today's issuance keys carry both, but
                // a future issue-only credential can never kill a license.
                .authorizeHttpRequests(auth -> auth.requestMatchers(
                                HttpMethod.POST, "/issuance/licenses/*/suspend", "/issuance/licenses/*/reinstate")
                        .hasAuthority("SCOPE_REVOKE")
                        .requestMatchers(HttpMethod.DELETE, "/issuance/licenses/*")
                        .hasAuthority("SCOPE_REVOKE")
                        .anyRequest()
                        .hasAuthority("SCOPE_ISSUE"))
                .exceptionHandling(ex -> ex.authenticationEntryPoint(errors).accessDeniedHandler(errors))
                .build();
    }

    /** Chain 3 — ADMIN (least specific, lowest precedence). Operators manage everything. */
    @Bean
    @Order(3)
    SecurityFilterChain adminChain(
            HttpSecurity http,
            AdminSessionService sessions,
            GrantmintAdminProperties properties,
            SecurityErrorResponder errors)
            throws Exception {
        return http.securityMatcher("/admin/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(
                        new AdminSessionAuthFilter(sessions, properties), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth.requestMatchers("/admin/auth/login")
                        .permitAll()
                        .anyRequest()
                        .hasRole("ADMIN"))
                .exceptionHandling(ex -> ex.authenticationEntryPoint(errors).accessDeniedHandler(errors))
                .build();
    }

    /**
     * Argon2id for low-entropy admin passwords. Uses Spring Security's hardened defaults (which
     * require BouncyCastle on the classpath).
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    /** System UTC clock for session expiry and {@code last_used_at}; overridable in tests. */
    @Bean
    Clock systemClock() {
        return Clock.systemUTC();
    }
}
