package dev.hg.grantmint.server.issuance;

import dev.hg.grantmint.server.domain.LicenseStatus;
import java.time.OffsetDateTime;

/**
 * The result of issuance: the short online {@code keyId}, the full signed offline {@code token}, the
 * persisted {@code status}, and the computed {@code expiresAt} (null for a perpetual license).
 */
public record IssuedLicense(String keyId, String token, LicenseStatus status, OffsetDateTime expiresAt) {}
