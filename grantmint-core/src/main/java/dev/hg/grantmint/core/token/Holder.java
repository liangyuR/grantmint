package dev.hg.grantmint.core.token;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The licensee carried in the {@code hld} claim: {@code { "n": name, "e": email }}.
 */
public record Holder(String name, String email) {

    public Holder {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(email, "email");
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
        if (!(name instanceof String n) || !(email instanceof String e)) {
            throw new IllegalArgumentException("Holder claim must have string 'n' and 'e'");
        }
        return new Holder(n, e);
    }
}
