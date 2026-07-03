package dev.hg.grantmint.server.logging;

import dev.hg.grantmint.server.security.AdminAuthentication;
import dev.hg.grantmint.server.security.ApiKeyAuthentication;
import dev.hg.grantmint.server.security.ApiKeyScope;
import org.springframework.security.core.Authentication;

/**
 * Maps the authenticated {@link Authentication} from one of the three auth schemes
 * (docs/features/ADMIN_AND_API_AUTH.md) to the {@code actor} MDC value in
 * docs/operations/MONITORING_LOGGING.md's structured-logging table:
 *
 * <ul>
 *   <li>{@code admin:<username>} — an authenticated admin session
 *   <li>{@code issuance-key:<keyPrefix>} — an issuance API key (mint/revoke)
 *   <li>{@code license-validation} — a validation API key; validation calls are not attributed to
 *       an individual key, only to the validation surface itself
 * </ul>
 *
 * <p>Never derives an actor string from anything secret — {@link ApiKeyAuthentication} never carries
 * the raw key past authentication, only the row id, scope, and display prefix.
 */
final class ActorResolver {

    /** The generic actor for validation-key-authenticated calls. */
    static final String LICENSE_VALIDATION = "license-validation";

    private ActorResolver() {}

    /** @return the {@code actor} MDC value for this authentication, or {@code null} if unauthenticated. */
    static String resolve(Authentication authentication) {
        if (authentication instanceof AdminAuthentication admin) {
            return "admin:" + admin.getName();
        }
        if (authentication instanceof ApiKeyAuthentication apiKey) {
            if (apiKey.scope() == ApiKeyScope.ISSUANCE) {
                return "issuance-key:" + apiKey.keyPrefix();
            }
            return LICENSE_VALIDATION;
        }
        return null;
    }
}
