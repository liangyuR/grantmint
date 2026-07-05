package dev.hg.grantmint.core.token;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The licensee carried in the {@code hld} claim: {@code { "n": name, "e": email }}.
 */
public record Holder(String name, String email) {

    public Holder {
        requireNonEmpty(name, "name");
        requireNonEmpty(email, "email");
    }

    /** The claim table requires non-empty holder fields; empty ones are malformed on the wire. */
    private static void requireNonEmpty(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isEmpty()) {
            throw new IllegalArgumentException("Holder '" + field + "' must be a non-empty string");
        }
    }

    /** The {@code hld} claim map ({@code n}/{@code e}). */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("n", name);
        map.put("e", email);
        return map;
    }

    /** Reconstruct from a parsed {@code hld} map. */
    public static Holder fromMap(Map<String, ?> map) {
        Objects.requireNonNull(map, "map");
        Object name = map.get("n");
        Object email = map.get("e");
        if (!(name instanceof String n) || !(email instanceof String e) || n.isEmpty() || e.isEmpty()) {
            throw new IllegalArgumentException("Holder claim must have non-empty string 'n' and 'e'");
        }
        return new Holder(n, e);
    }
}
