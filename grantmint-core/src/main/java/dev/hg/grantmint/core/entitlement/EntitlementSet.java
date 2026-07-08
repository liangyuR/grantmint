package dev.hg.grantmint.core.entitlement;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * An immutable collection of {@link Entitlement}s keyed by normalized key — the logical contents of
 * a token's {@code ent} claim.
 *
 * <p>{@link #encode()} produces the flat {@code key -> value} map (booleans, integers, strings) that
 * {@link dev.hg.grantmint.core.codec.CanonicalJson} serializes; {@link #decode(Map)} infers the
 * entitlement type from each JSON value's runtime type. The pair round-trips: decoding an encoded
 * set yields an equal set, which is what the entitlement property test asserts.
 *
 * <p>See docs/features/ENTITLEMENTS.md.
 */
public final class EntitlementSet {

    private static final EntitlementSet EMPTY = new EntitlementSet(Map.of());

    /** Keyed by normalized entitlement key. */
    private final Map<String, Entitlement> byKey;

    private EntitlementSet(Map<String, Entitlement> byKey) {
        this.byKey = byKey;
    }

    /** The empty entitlement set. */
    public static EntitlementSet empty() {
        return EMPTY;
    }

    /** Build from explicit entitlements; later entries with the same key win. */
    public static EntitlementSet of(Entitlement... entitlements) {
        Objects.requireNonNull(entitlements, "entitlements");
        Map<String, Entitlement> map = new LinkedHashMap<>();
        for (Entitlement e : entitlements) {
            map.put(e.key(), e);
        }
        return map.isEmpty() ? EMPTY : new EntitlementSet(Collections.unmodifiableMap(map));
    }

    /** Build from a collection of entitlements. */
    public static EntitlementSet of(Collection<Entitlement> entitlements) {
        Objects.requireNonNull(entitlements, "entitlements");
        Map<String, Entitlement> map = new LinkedHashMap<>();
        for (Entitlement e : entitlements) {
            map.put(e.key(), e);
        }
        return map.isEmpty() ? EMPTY : new EntitlementSet(Collections.unmodifiableMap(map));
    }

    /**
     * Decode a flat {@code ent} map (as produced by {@link #encode()} or parsed from a token) into an
     * entitlement set, inferring each entitlement's type from its value:
     *
     * <ul>
     *   <li>{@link Boolean} → {@link EntitlementType#FLAG}
     *   <li>{@link Integer}/{@link Long}/{@link BigInteger} → {@link EntitlementType#LIMIT}
     *   <li>{@link String} → {@link EntitlementType#STRING}
     * </ul>
     *
     * @throws IllegalArgumentException for any other value type (e.g. a fractional number or null),
     *     or for a key that is not already in canonical form ({@link EntitlementKey#isCanonical}) —
     *     normalizing here instead would let two JSON-distinct keys (e.g. {@code "MAX_DEVICES"} and
     *     {@code "max_devices"}) silently collapse last-wins, a cross-SDK parity hazard; a canonical
     *     issuer never emits such keys, so they are rejected outright
     */
    public static EntitlementSet decode(Map<String, ?> ent) {
        Objects.requireNonNull(ent, "ent");
        Map<String, Entitlement> map = new LinkedHashMap<>();
        for (Map.Entry<String, ?> entry : ent.entrySet()) {
            if (!EntitlementKey.isCanonical(entry.getKey())) {
                throw new IllegalArgumentException(
                        "Entitlement key '" + entry.getKey() + "' is not in canonical snake_case form");
            }
            map.put(entry.getKey(), toEntitlement(entry.getKey(), entry.getValue()));
        }
        return map.isEmpty() ? EMPTY : new EntitlementSet(Collections.unmodifiableMap(map));
    }

    private static Entitlement toEntitlement(String key, Object value) {
        if (value instanceof Boolean b) {
            return Entitlement.flag(key, b);
        }
        if (value instanceof Long l) {
            return Entitlement.limit(key, l);
        }
        if (value instanceof Integer i) {
            return Entitlement.limit(key, i.longValue());
        }
        if (value instanceof BigInteger bi) {
            try {
                return Entitlement.limit(key, bi.longValueExact());
            } catch (ArithmeticException overflow) {
                throw new IllegalArgumentException(
                        "Entitlement limit '" + key + "' exceeds the supported 64-bit range", overflow);
            }
        }
        if (value instanceof String s) {
            return Entitlement.string(key, s);
        }
        throw new IllegalArgumentException("Unsupported entitlement value for '" + key + "': "
                + (value == null ? "null" : value.getClass().getName()));
    }

    /**
     * Encode to a flat map suitable for canonical JSON serialization. Returns a sorted map so callers
     * that inspect it see a stable order; canonical serialization re-sorts regardless.
     */
    public Map<String, Object> encode() {
        Map<String, Object> out = new TreeMap<>();
        for (Entitlement e : byKey.values()) {
            out.put(e.key(), e.value());
        }
        return out;
    }

    /** The entitlement for {@code key}, if present. */
    public Optional<Entitlement> get(String key) {
        return Optional.ofNullable(byKey.get(EntitlementKey.normalize(key)));
    }

    /** Whether the flag {@code key} is present and {@code true}. Absent or non-flag → {@code false}. */
    public boolean isEnabled(String key) {
        Entitlement e = byKey.get(EntitlementKey.normalize(key));
        return e != null && e.type() == EntitlementType.FLAG && e.asFlag();
    }

    /** The limit for {@code key}, or {@code defaultValue} if absent or not a limit. */
    public long limit(String key, long defaultValue) {
        Entitlement e = byKey.get(EntitlementKey.normalize(key));
        return (e != null && e.type() == EntitlementType.LIMIT) ? e.asLimit() : defaultValue;
    }

    /** The string value for {@code key}, or {@code defaultValue} if absent or not a string. */
    public String string(String key, String defaultValue) {
        Entitlement e = byKey.get(EntitlementKey.normalize(key));
        return (e != null && e.type() == EntitlementType.STRING) ? e.asString() : defaultValue;
    }

    /** An unmodifiable view of all entitlements. */
    public Collection<Entitlement> entitlements() {
        return Collections.unmodifiableCollection(byKey.values());
    }

    public boolean isEmpty() {
        return byKey.isEmpty();
    }

    public int size() {
        return byKey.size();
    }

    @Override
    public boolean equals(Object o) {
        return this == o || (o instanceof EntitlementSet other && byKey.equals(other.byKey));
    }

    @Override
    public int hashCode() {
        return byKey.hashCode();
    }

    @Override
    public String toString() {
        return "EntitlementSet" + byKey.keySet();
    }
}
