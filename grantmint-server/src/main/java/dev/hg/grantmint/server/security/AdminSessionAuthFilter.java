package dev.hg.grantmint.server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Scheme 1 — authenticates an operator via an admin session token, accepted either as
 * {@code Authorization: Bearer gm_sess_…} (for CLI/API clients, when enabled) or as the session
 * cookie (for browser flows). A resolved session yields a {@code ROLE_ADMIN} authentication.
 * See docs/features/ADMIN_AND_API_AUTH.md.
 */
public class AdminSessionAuthFilter extends OncePerRequestFilter {

    private final AdminSessionService sessions;
    private final GrantmintAdminProperties properties;

    public AdminSessionAuthFilter(AdminSessionService sessions, GrantmintAdminProperties properties) {
        this.sessions = sessions;
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String token = presentedToken(request, properties);
        if (token != null) {
            sessions.resolve(token).ifPresent(principal -> SecurityContextHolder.getContext()
                    .setAuthentication(new AdminAuthentication(principal)));
        }
        chain.doFilter(request, response);
    }

    /**
     * The session token this request presents: the bearer token when bearer auth is enabled, else
     * the session cookie. Shared with the auth controller so logout revokes exactly the session the
     * request authenticated with, however it was carried.
     */
    public static String presentedToken(HttpServletRequest request, GrantmintAdminProperties properties) {
        if (properties.session().bearerEnabled()) {
            String bearer = BearerTokens.extract(request);
            if (bearer != null) {
                return bearer;
            }
        }
        return sessionCookie(request, properties);
    }

    /** The raw session-cookie value, or null when absent. */
    public static String sessionCookie(HttpServletRequest request, GrantmintAdminProperties properties) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            String cookieName = properties.session().cookieName();
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
