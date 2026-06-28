package dev.hg.grantmint.core.token;

import dev.hg.grantmint.core.entitlement.EntitlementSet;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The logical claim set carried in segment B — everything a client needs to answer "is this license
 * authentic and unexpired, and what does it entitle?".
 *
 * <p>Field names map to the short wire keys to keep tokens small ({@code ver}, {@code lid}, {@code
 * kid}, {@code prd}, {@code pol}, {@code hld}, {@code iat}, {@code nbf}, {@code exp}, {@code ent},
 * {@code con}, {@code seat}). Times are Unix epoch seconds in UTC — integers, never localized
 * strings. {@code exp} is {@code null} for a perpetual license. Optional claims ({@code nbf}, {@code
 * con}, {@code seat}) are omitted from the wire when absent.
 *
 * <p>See docs/features/LICENSE_TOKEN_FORMAT.md (The logical claim set).
 */
public record TokenPayload(
        int ver,
        String lid,
        String kid,
        String prd,
        String pol,
        Holder holder,
        long iat,
        Long nbf,
        Long exp,
        EntitlementSet entitlements,
        Map<String, Object> constraints,
        Integer seat) {

    /** The current token format version. */
    public static final int CURRENT_VERSION = 1;

    public TokenPayload {
        Objects.requireNonNull(lid, "lid");
        Objects.requireNonNull(kid, "kid");
        Objects.requireNonNull(prd, "prd");
        Objects.requireNonNull(pol, "pol");
        Objects.requireNonNull(holder, "holder");
        entitlements = entitlements == null ? EntitlementSet.empty() : entitlements;
        constraints = normalizeConstraints(constraints);
    }

    /** Build the ordered claim map for canonical serialization. Optional claims are omitted when null. */
    public Map<String, Object> toClaimMap() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("ver", ver);
        claims.put("lid", lid);
        claims.put("kid", kid);
        claims.put("prd", prd);
        claims.put("pol", pol);
        claims.put("hld", holder.toMap());
        claims.put("iat", iat);
        if (nbf != null) {
            claims.put("nbf", nbf);
        }
        claims.put("exp", exp); // required claim; null = perpetual
        claims.put("ent", entitlements.encode());
        if (constraints != null && !constraints.isEmpty()) {
            claims.put("con", constraints);
        }
        if (seat != null) {
            claims.put("seat", seat);
        }
        return claims;
    }

    /** Reconstruct a payload from a parsed JSON claim map. */
    @SuppressWarnings("unchecked")
    public static TokenPayload fromClaimMap(Map<String, ?> map) {
        Objects.requireNonNull(map, "map");
        EntitlementSet ent = map.get("ent") instanceof Map<?, ?> e
                ? EntitlementSet.decode((Map<String, ?>) e)
                : EntitlementSet.empty();
        Map<String, Object> con =
                map.get("con") instanceof Map<?, ?> c ? new LinkedHashMap<>((Map<String, Object>) c) : null;
        Holder holder = Holder.fromMap(requireMap(map, "hld"));
        return new TokenPayload(
                asInt(map, "ver"),
                asString(map, "lid"),
                asString(map, "kid"),
                asString(map, "prd"),
                asString(map, "pol"),
                holder,
                asLong(map, "iat"),
                asLongOrNull(map, "nbf"),
                asLongOrNull(map, "exp"),
                ent,
                con,
                asIntOrNull(map, "seat"));
    }

    private static Map<String, Object> normalizeConstraints(Map<String, Object> constraints) {
        if (constraints == null || constraints.isEmpty()) {
            return constraints;
        }
        // Normalize integers to Long so a constraint set round-trips through parse/serialize equal by
        // value (the JSON parser yields Long for every integer).
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : constraints.entrySet()) {
            Object v = entry.getValue();
            out.put(entry.getKey(), v instanceof Integer i ? i.longValue() : v);
        }
        return Collections.unmodifiableMap(out);
    }

    private static Map<String, ?> requireMap(Map<String, ?> map, String key) {
        if (!(map.get(key) instanceof Map<?, ?> m)) {
            throw new IllegalArgumentException("Claim '" + key + "' must be an object");
        }
        @SuppressWarnings("unchecked")
        Map<String, ?> typed = (Map<String, ?>) m;
        return typed;
    }

    private static String asString(Map<String, ?> map, String key) {
        if (!(map.get(key) instanceof String s)) {
            throw new IllegalArgumentException("Claim '" + key + "' must be a string");
        }
        return s;
    }

    private static long asLong(Map<String, ?> map, String key) {
        if (!(map.get(key) instanceof Number n)) {
            throw new IllegalArgumentException("Claim '" + key + "' must be a number");
        }
        return n.longValue();
    }

    private static Long asLongOrNull(Map<String, ?> map, String key) {
        Object v = map.get(key);
        if (v == null) {
            return null;
        }
        if (!(v instanceof Number n)) {
            throw new IllegalArgumentException("Claim '" + key + "' must be a number or null");
        }
        return n.longValue();
    }

    private static int asInt(Map<String, ?> map, String key) {
        return Math.toIntExact(asLong(map, key));
    }

    private static Integer asIntOrNull(Map<String, ?> map, String key) {
        Long v = asLongOrNull(map, key);
        return v == null ? null : Math.toIntExact(v);
    }
}
