package dev.hg.grantmint.client;

import java.util.OptionalLong;

/**
 * Ergonomic feature gating over {@link LicenseValidator#current()}: flags, numeric limits, and a
 * throwing {@code require} for hard gates. An invalid license grants nothing — every check answers
 * against the entitlements of a currently-valid status only.
 */
public class EntitlementChecker {

    private final LicenseValidator validator;

    public EntitlementChecker(LicenseValidator validator) {
        this.validator = validator;
    }

    /** {@code true} only when the license is valid AND carries the flag as {@code true}. */
    public boolean isEnabled(String key) {
        LicenseStatus status = validator.current();
        return status.valid() && Boolean.TRUE.equals(status.entitlements().get(key));
    }

    /** The numeric limit, when the license is valid and carries one. {@code -1} means unlimited. */
    public OptionalLong limit(String key) {
        LicenseStatus status = validator.current();
        if (status.valid() && status.entitlements().get(key) instanceof Number limit) {
            return OptionalLong.of(limit.longValue());
        }
        return OptionalLong.empty();
    }

    /** The string entitlement value, or {@code null} when absent or the license is invalid. */
    public String value(String key) {
        LicenseStatus status = validator.current();
        return status.valid() && status.entitlements().get(key) instanceof String value ? value : null;
    }

    /** Hard gate: throws unless the flag is enabled on a valid license. */
    public void require(String key) {
        if (!isEnabled(key)) {
            throw new EntitlementDeniedException(key);
        }
    }
}
