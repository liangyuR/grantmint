package dev.hg.grantmint.server.domain;

import java.util.Locale;

/**
 * License lifecycle status.
 *
 * <p>Persisted as lowercase {@code text} guarded by the {@code ck_licenses_status} CHECK
 * constraint ({@code created → active → suspended → expired → revoked}). The wire form is
 * lowercase, so this enum carries an explicit {@link #wire()} value rather than relying on
 * {@link Enum#name()} (which is uppercase and would violate the constraint). See
 * docs/architecture/DATABASE_SCHEMA.md and docs/features/LICENSE_LIFECYCLE.md.
 */
public enum LicenseStatus {
    CREATED,
    ACTIVE,
    SUSPENDED,
    EXPIRED,
    REVOKED;

    /** The lowercase token stored in the database. */
    public String wire() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** Parse a database/wire token (case-insensitive) into the enum. */
    public static LicenseStatus fromWire(String value) {
        return LicenseStatus.valueOf(value.toUpperCase(Locale.ROOT));
    }
}
