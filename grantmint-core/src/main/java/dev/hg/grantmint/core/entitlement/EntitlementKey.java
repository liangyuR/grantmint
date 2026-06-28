package dev.hg.grantmint.core.entitlement;

import java.util.Locale;
import java.util.Objects;

/**
 * Normalization for entitlement keys.
 *
 * <p>Keys are {@code snake_case} lowercase ASCII and are compared after normalization so a key set
 * on a {@code tr_TR} server and read on a {@code de_DE} client still matches. Normalization uses
 * {@link Locale#ROOT} — never the default locale (the Turkish dotless-i trap). See
 * docs/features/ENTITLEMENTS.md (Naming conventions).
 */
public final class EntitlementKey {

    private EntitlementKey() {}

    /** Trim surrounding whitespace and lower-case with {@link Locale#ROOT}. */
    public static String normalize(String key) {
        Objects.requireNonNull(key, "key");
        String normalized = key.strip().toLowerCase(Locale.ROOT);
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("Entitlement key must not be blank");
        }
        return normalized;
    }
}
