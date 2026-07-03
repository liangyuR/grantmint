package dev.hg.grantmint.server.security;

import dev.hg.grantmint.server.security.ApiKeyService.ResolvedKey;
import java.util.UUID;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * The authenticated identity behind a valid issuance or validation API key. The principal is the
 * scoped product id, so a downstream controller can compare it against the product of the target
 * resource and reject cross-product access. The raw key is never carried forward.
 */
public final class ApiKeyAuthentication extends AbstractAuthenticationToken {

    private final transient ResolvedKey key;

    public ApiKeyAuthentication(ResolvedKey key) {
        super(AuthorityUtils.createAuthorityList(key.scope().authorities().toArray(String[]::new)));
        this.key = key;
        setAuthenticated(true);
    }

    /** The API-key row id, for audit attribution. */
    public UUID apiKeyId() {
        return key.apiKeyId();
    }

    /** The product this key is scoped to (null only for global admin keys). */
    public UUID productId() {
        return key.productId();
    }

    public ApiKeyScope scope() {
        return key.scope();
    }

    /**
     * The key's display prefix (e.g. {@code gm_live_ab12}) — a safe, non-secret identifier for
     * structured-log actor attribution ({@code issuance-key:<prefix>} in
     * docs/operations/MONITORING_LOGGING.md). The raw key is never available here.
     */
    public String keyPrefix() {
        return key.keyPrefix();
    }

    @Override
    public Object getCredentials() {
        return ""; // never carry the raw key forward
    }

    @Override
    public Object getPrincipal() {
        return key.productId();
    }
}
