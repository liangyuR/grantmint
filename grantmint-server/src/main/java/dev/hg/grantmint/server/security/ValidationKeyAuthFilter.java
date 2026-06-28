package dev.hg.grantmint.server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Scheme 3 — authenticates client apps in the field via the {@code X-Grantmint-Validation} header.
 * A resolved key yields a product-scoped {@code SCOPE_VALIDATION} authentication; anything else
 * falls through to the chain's {@code denyAll}/authority rules, which the entry point renders as
 * 401/403. See docs/features/ADMIN_AND_API_AUTH.md.
 */
public class ValidationKeyAuthFilter extends OncePerRequestFilter {

    /** Header carrying the {@code gm_val_…} validation key. */
    public static final String HEADER = "X-Grantmint-Validation";

    private final ApiKeyService apiKeys;

    public ValidationKeyAuthFilter(ApiKeyService apiKeys) {
        this.apiKeys = apiKeys;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String presented = request.getHeader(HEADER);
        if (presented != null && presented.startsWith("gm_val_")) {
            apiKeys.resolve(presented, ApiKeyScope.VALIDATION).ifPresent(resolved -> SecurityContextHolder.getContext()
                    .setAuthentication(new ApiKeyAuthentication(resolved)));
        }
        chain.doFilter(request, response);
    }
}
