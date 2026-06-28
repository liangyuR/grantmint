package dev.hg.grantmint.server.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;

/** Extracts a bearer credential from the {@code Authorization} header. */
public final class BearerTokens {

    private static final String PREFIX = "Bearer ";

    private BearerTokens() {}

    /** The token after {@code Bearer }, or null if the header is absent or malformed. */
    public static String extract(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(PREFIX)) {
            return null;
        }
        String token = header.substring(PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }
}
