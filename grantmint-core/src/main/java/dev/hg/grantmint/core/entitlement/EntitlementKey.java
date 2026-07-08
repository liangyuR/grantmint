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

    /**
     * Whether {@code key} is already in canonical wire form: {@code ^[a-z][a-z0-9_]{0,62}$} — the
     * same grammar the server enforces at entitlement creation ({@code ck_entitlements_code_fmt}).
     *
     * <p>Verifiers reject a token whose {@code ent} carries a non-canonical key rather than
     * normalizing it: two JSON-distinct keys that collide only after normalization (e.g. {@code
     * "MAX_DEVICES"} and {@code "max_devices"}) would otherwise merge last-wins in one SDK and stay
     * distinct in another, splitting entitlement semantics across implementations. A pure ASCII
     * character-class check is byte-deterministic in every language, so all five verifiers can pin
     * the identical rule with no Unicode case-folding parity risk.
     */
    public static boolean isCanonical(String key) {
        Objects.requireNonNull(key, "key");
        int length = key.length();
        if (length < 1 || length > 63) {
            return false;
        }
        char first = key.charAt(0);
        if (first < 'a' || first > 'z') {
            return false;
        }
        for (int i = 1; i < length; i++) {
            char c = key.charAt(i);
            boolean lower = c >= 'a' && c <= 'z';
            boolean digit = c >= '0' && c <= '9';
            if (!lower && !digit && c != '_') {
                return false;
            }
        }
        return true;
    }
}
