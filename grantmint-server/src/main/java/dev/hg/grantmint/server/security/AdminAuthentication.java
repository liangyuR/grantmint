package dev.hg.grantmint.server.security;

import java.util.List;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * The authenticated identity behind a valid admin session (Scheme 1). Confers {@code ROLE_ADMIN}
 * and carries the {@link AdminPrincipal} for authorization and audit attribution.
 */
public final class AdminAuthentication extends AbstractAuthenticationToken {

    private final transient AdminPrincipal principal;

    public AdminAuthentication(AdminPrincipal principal) {
        super(List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        this.principal = principal;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return ""; // never carry the session token forward
    }

    @Override
    public AdminPrincipal getPrincipal() {
        return principal;
    }

    @Override
    public String getName() {
        return principal.username();
    }
}
