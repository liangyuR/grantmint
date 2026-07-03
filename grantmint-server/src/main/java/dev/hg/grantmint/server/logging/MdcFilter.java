package dev.hg.grantmint.server.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Populates the request-scoped {@code requestId} and {@code actor} MDC keys for every request, per
 * docs/operations/MONITORING_LOGGING.md ("MDC fields"). {@code keyId}/{@code licenseId}/{@code
 * productId} are populated by the issuance/validation service layer itself, which is where those
 * values are actually known.
 *
 * <p>Registered by {@link LoggingFilterConfig} to run <em>after</em> the Spring Security filter
 * chain and before the {@code DispatcherServlet}, so {@link SecurityContextHolder}'s {@link
 * org.springframework.security.core.context.SecurityContext} is already populated by the time this
 * filter runs — {@code actor} reflects the authenticated admin session or API key without this class
 * ever touching credentials itself. See {@link ActorResolver}.
 *
 * <p>{@link MDC#clear()} always runs in a {@code finally} block — thread pools reuse threads, so a
 * stale MDC value would otherwise leak into an unrelated later request.
 */
public class MdcFilter extends OncePerRequestFilter {

    /** Client-supplied correlation id header; a random UUID is generated when absent or blank. */
    public static final String REQUEST_ID_HEADER = "X-Request-Id";

    static final String MDC_REQUEST_ID = "requestId";
    static final String MDC_ACTOR = "actor";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            MDC.put(MDC_REQUEST_ID, requestId(request));
            String actor =
                    ActorResolver.resolve(SecurityContextHolder.getContext().getAuthentication());
            if (actor != null) {
                MDC.put(MDC_ACTOR, actor);
            }
            chain.doFilter(request, response);
        } finally {
            MDC.clear(); // always clear — thread pools reuse threads
        }
    }

    private static String requestId(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(REQUEST_ID_HEADER))
                .filter(value -> !value.isBlank())
                .orElseGet(() -> UUID.randomUUID().toString());
    }
}
