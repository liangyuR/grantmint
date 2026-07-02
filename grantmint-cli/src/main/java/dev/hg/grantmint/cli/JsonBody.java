package dev.hg.grantmint.cli;

import dev.hg.grantmint.core.codec.CanonicalJson;
import java.util.Map;

/**
 * Thin wrapper around {@code grantmint-core}'s canonical JSON codec for the CLI's HTTP-backed
 * commands ({@code issue}, {@code revoke}). {@link CanonicalJson} already implements a correct,
 * tested JSON encoder/decoder (string escaping, integer-only numbers) so the CLI does not need a
 * second hand-rolled implementation; canonical key ordering is irrelevant for a request/response
 * body, only round-trip correctness matters here.
 */
final class JsonBody {

    private JsonBody() {}

    /** Serialize a request body map to a JSON string. */
    static String serialize(Map<String, Object> fields) {
        return CanonicalJson.serializeToString(fields);
    }

    /** Best-effort parse of a response body; returns {@code null} if it is not parseable JSON. */
    static Object parseOrNull(String body) {
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            return CanonicalJson.parse(body);
        } catch (RuntimeException notJson) {
            return null;
        }
    }

    /** The string value of {@code key} in a parsed JSON object, or {@code null} if absent/not a string. */
    static String stringField(Object json, String key) {
        if (json instanceof Map<?, ?> map && map.get(key) instanceof String value) {
            return value;
        }
        return null;
    }
}
