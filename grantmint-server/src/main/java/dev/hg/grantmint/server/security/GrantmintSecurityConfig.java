package dev.hg.grantmint.server.security;

import static org.springframework.security.config.Customizer.withDefaults;

import jakarta.servlet.DispatcherType;
import java.time.Clock;
import java.util.List;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Wires the three independent, path-scoped {@link SecurityFilterChain}s — the code-level expression
 * of blast-radius isolation — plus a lowest-precedence catch-all that default-denies everything
 * else. Each surface is evaluated by exactly one chain, ordered most-specific first: validation
 * (hottest path) → issuance → admin → catch-all. A route added outside the known prefixes is
 * therefore denied until someone deliberately opens it, never silently public (2026-07-05 audit,
 * GRANTMINT-146). See docs/features/ADMIN_AND_API_AUTH.md.
 *
 * <p>All chains are stateless (our own server-side session store, never a Spring HTTP session).
 * The validation and issuance chains are CSRF-disabled — header/bearer credentials cannot be sent
 * ambiently by a browser. The admin chain enforces CSRF for cookie-authenticated writes only (the
 * M11 dashboard flow); see the admin chain below.
 */
@Configuration
@EnableConfigurationProperties({
    GrantmintAdminProperties.class,
    GrantmintOpenApiProperties.class,
    GrantmintCorsProperties.class
})
public class GrantmintSecurityConfig {

    /** OpenAPI doc + Swagger UI paths (springdoc), gated by {@link GrantmintOpenApiProperties}. */
    private static final String[] OPENAPI_PATHS = {
        "/v3/api-docs", "/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**"
    };

    /**
     * Chain 0 — OPENAPI docs. Most specific so it wins for doc/UI paths before any functional chain.
     * Its policy is configurable because these endpoints sit outside the three auth surfaces:
     * admin-gated by default ({@link GrantmintOpenApiProperties}), openable to public or fully
     * disabled in production.
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
                .cors(withDefaults())
                .headers(GrantmintSecurityConfig::explicitResponseHeaders)
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
                .cors(withDefaults())
                .headers(GrantmintSecurityConfig::explicitResponseHeaders)
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
                .cors(withDefaults())
                .headers(GrantmintSecurityConfig::explicitResponseHeaders)
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
        // CSRF is a cookie problem: it protects exactly the requests a browser could be tricked
        // into sending ambiently. State-changing requests carrying the session COOKIE (and no
        // bearer header) must present the double-submit X-XSRF-TOKEN; bearer-authenticated CLI/API
        // calls and the login exchange (whose auth IS the credentials, and whose cookie is
        // SameSite=Strict anyway) are exempt. The token rides a JS-readable XSRF-TOKEN cookie for
        // the SPA to echo back.
        CookieCsrfTokenRepository csrfRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        // Pin the XSRF-TOKEN cookie's Secure attribute to the same property the session cookie
        // honors, instead of Spring's request.isSecure() default — behind a TLS-terminating proxy
        // the request looks plain-HTTP and the default would silently drop the attribute.
        csrfRepository.setCookieCustomizer(
                cookie -> cookie.secure(properties.session().cookieSecure()));
        CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();
        // Resolve the token eagerly on every request so the XSRF-TOKEN cookie is actually written.
        csrfHandler.setCsrfRequestAttributeName(null);
        RequestMatcher cookieAuthenticatedWrite = request -> CsrfFilter.DEFAULT_CSRF_MATCHER.matches(request)
                && !request.getRequestURI().equals("/admin/auth/login")
                && request.getHeader("Authorization") == null
                && AdminSessionAuthFilter.sessionCookie(request, properties) != null;
        return http.securityMatcher("/admin/**")
                .csrf(csrf -> csrf.csrfTokenRepository(csrfRepository)
                        .csrfTokenRequestHandler(csrfHandler)
                        .requireCsrfProtectionMatcher(cookieAuthenticatedWrite))
                .cors(withDefaults())
                .headers(GrantmintSecurityConfig::explicitResponseHeaders)
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
     * Chain 4 — CATCH-ALL default-deny, no {@code securityMatcher} so it collects every request the
     * four scoped chains did not claim. The explicit permits are the two surfaces that authenticate
     * by other means: webhooks verify the provider's HMAC over the raw body in the controller
     * (verify-before-parse — there is no bearer/cookie credential a filter could check), and the
     * actuator lives on the loopback-bound management port, which inherits this filter chain; on the
     * public port the actuator paths have no handler and 404 exactly as before. ERROR dispatches are
     * permitted so Boot's internal re-dispatch to {@code /error} (a 404 inside a secured chain, an
     * exception no advice handled) keeps rendering its real status — a direct external request to
     * {@code /error} is a REQUEST dispatch and stays denied.
     */
    @Bean
    @Order(4)
    SecurityFilterChain catchAllDenyChain(HttpSecurity http, SecurityErrorResponder errors) throws Exception {
        return http.csrf(csrf -> csrf.disable())
                .cors(withDefaults())
                .headers(GrantmintSecurityConfig::explicitResponseHeaders)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.dispatcherTypeMatchers(DispatcherType.ERROR)
                        .permitAll()
                        .requestMatchers("/v2/licenses/challenges", "/v2/licenses/activate")
                        .permitAll()
                        .requestMatchers("/webhooks/**")
                        .permitAll()
                        .requestMatchers("/actuator/**")
                        .permitAll()
                        .anyRequest()
                        .denyAll())
                .exceptionHandling(ex -> ex.authenticationEntryPoint(errors).accessDeniedHandler(errors))
                .build();
    }

    /**
     * One CORS source shared by every chain. With no configured origins it answers {@code null} for
     * every request, so Spring emits NO CORS headers and browsers enforce same-origin — the shipped
     * default. With origins configured ({@link GrantmintCorsProperties}), exact-match credentialed
     * CORS covers the dashboard's cookie/XSRF flows and the API-key headers; preflights from any
     * unlisted origin are rejected. Previously no CORS policy existed at all — safe, but only by
     * omission (2026-07 audit, GRANTMINT-168).
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource(GrantmintCorsProperties cors) {
        if (cors.allowedOrigins().isEmpty()) {
            return request -> null;
        }
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.copyOf(cors.allowedOrigins()));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "X-XSRF-TOKEN",
                "X-Grantmint-Issuance-Key",
                "X-Grantmint-License-Key"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * The explicit response-header policy every chain applies — previously Spring Security's
     * implicit defaults, safe but not auditable (2026-07 audit, GRANTMINT-168). nosniff, DENY
     * framing, HSTS, and no-store caching restate the defaults as declared policy;
     * {@code Referrer-Policy: no-referrer} is additional — a key ID or token fragment in an
     * operator's URL must never leak into a third party's {@code Referer} header.
     */
    private static void explicitResponseHeaders(HeadersConfigurer<HttpSecurity> headers) {
        headers.contentTypeOptions(withDefaults())
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                .httpStrictTransportSecurity(withDefaults())
                .referrerPolicy(ref -> ref.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                .cacheControl(withDefaults());
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
