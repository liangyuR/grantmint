package dev.hg.grantmint.server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Scheme 2 — authenticates a backend/CI caller via an {@code Authorization: Bearer gm_live_…} (or
 * {@code gm_test_…}) issuance key, granting {@code SCOPE_ISSUE} and {@code SCOPE_REVOKE}.
 *
 * <p>It resolves <em>any</em> API-key namespace (not just issuance) so a real-but-wrong-scope key —
 * a validation key sent here — still authenticates and is then rejected by the chain's authority
 * rule as 403 ("real key, wrong scope") rather than 401. Session tokens ({@code gm_sess_…}) are
 * left alone for the admin chain. See docs/features/ADMIN_AND_API_AUTH.md.
 */
public class IssuanceKeyAuthFilter extends OncePerRequestFilter {

    private final ApiKeyService apiKeys;

    public IssuanceKeyAuthFilter(ApiKeyService apiKeys) {
        this.apiKeys = apiKeys;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String presented = BearerTokens.extract(request);
        if (presented != null && presented.startsWith("gm_") && !presented.startsWith("gm_sess_")) {
            apiKeys.resolveByNamespace(presented).ifPresent(resolved -> SecurityContextHolder.getContext()
                    .setAuthentication(new ApiKeyAuthentication(resolved)));
        }
        chain.doFilter(request, response);
    }
}
