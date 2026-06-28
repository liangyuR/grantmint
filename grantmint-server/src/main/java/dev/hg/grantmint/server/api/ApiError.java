package dev.hg.grantmint.server.api;

/**
 * Compact error envelope shared by the REST surface, mirroring the security responder's shape so a
 * client sees one consistent {@code {error, message}} body whether the failure came from the
 * security filters or a controller.
 *
 * @param error a short machine-readable code, e.g. {@code not_found}
 * @param message a human-readable explanation
 */
public record ApiError(String error, String message) {}
