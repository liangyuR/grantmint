package dev.hg.grantmint.server.security;

import java.util.UUID;

/**
 * The authenticated identity behind a valid admin session, reduced to what authorization and audit
 * need. Carried as the principal of an {@link AdminAuthentication}.
 *
 * @param adminUserId the operator's id, for attribution in the audit trail
 * @param username the operator's username
 */
public record AdminPrincipal(UUID adminUserId, String username) {}
