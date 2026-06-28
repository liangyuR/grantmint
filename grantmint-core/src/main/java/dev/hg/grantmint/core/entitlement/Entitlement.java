package dev.hg.grantmint.core.entitlement;

import java.util.Objects;

/**
 * A single named capability or limit attached to a license.
 *
 * <p>The {@code value} is constrained to the kind declared by {@code type}: {@link Boolean} for
 * {@link EntitlementType#FLAG}, {@link Long} for {@link EntitlementType#LIMIT}, {@link String} for
 * {@link EntitlementType#STRING}. The key is normalized at construction (see {@link EntitlementKey}).
 *
 * <p>Use the {@link #flag}, {@link #limit}, {@link #string} factories rather than the canonical
 * constructor.
 */
public record Entitlement(String key, EntitlementType type, Object value) {

    public Entitlement {
        key = EntitlementKey.normalize(key);
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(value, "value");
        switch (type) {
            case FLAG -> requireType(value, Boolean.class, type);
            case LIMIT -> requireType(value, Long.class, type);
            case STRING -> requireType(value, String.class, type);
        }
    }

    /** A boolean feature flag. */
    public static Entitlement flag(String key, boolean enabled) {
        return new Entitlement(key, EntitlementType.FLAG, enabled);
    }

    /** A numeric limit ({@code -1} denotes unlimited). */
    public static Entitlement limit(String key, long value) {
        return new Entitlement(key, EntitlementType.LIMIT, value);
    }

    /** A string-valued entitlement. */
    public static Entitlement string(String key, String value) {
        return new Entitlement(key, EntitlementType.STRING, value);
    }

    /** The flag value; throws if this is not a {@link EntitlementType#FLAG}. */
    public boolean asFlag() {
        require(EntitlementType.FLAG);
        return (Boolean) value;
    }

    /** The limit value; throws if this is not a {@link EntitlementType#LIMIT}. */
    public long asLimit() {
        require(EntitlementType.LIMIT);
        return (Long) value;
    }

    /** The string value; throws if this is not a {@link EntitlementType#STRING}. */
    public String asString() {
        require(EntitlementType.STRING);
        return (String) value;
    }

    /** Whether this limit is the unlimited sentinel ({@code -1}). */
    public boolean isUnlimited() {
        return type == EntitlementType.LIMIT && (Long) value == -1L;
    }

    private void require(EntitlementType expected) {
        if (type != expected) {
            throw new IllegalStateException("Entitlement '" + key + "' is " + type + ", not " + expected);
        }
    }

    private static void requireType(Object value, Class<?> expected, EntitlementType type) {
        if (!expected.isInstance(value)) {
            throw new IllegalArgumentException(type + " entitlement value must be " + expected.getSimpleName()
                    + ", was " + value.getClass().getSimpleName());
        }
    }
}
