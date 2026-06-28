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
        String token = presentedToken(request);
        if (token != null) {
            sessions.resolve(token).ifPresent(principal -> SecurityContextHolder.getContext()
                    .setAuthentication(new AdminAuthentication(principal)));
        }
        chain.doFilter(request, response);
    }

    /** Prefer the bearer token (when bearer auth is enabled), else fall back to the session cookie. */
    private String presentedToken(HttpServletRequest request) {
        if (properties.session().bearerEnabled()) {
            String bearer = BearerTokens.extract(request);
            if (bearer != null) {
                return bearer;
            }
        }
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
