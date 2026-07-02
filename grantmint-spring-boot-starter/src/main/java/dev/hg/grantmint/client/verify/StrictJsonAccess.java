package dev.hg.grantmint.client.verify;

import java.util.Map;

/**
 * Total (non-throwing) JSON-object parsing for server <em>responses</em> — the same strict reader
 * used on token segments, but a response that fails to parse is an "unreachable/garbled server"
 * condition to handle, not an exception to propagate. Token verification never uses this: signed
 * bytes are held to the throwing strict parse.
 */
public final class StrictJsonAccess {

    /** The parsed object, or {@code null} when the text is not a strict single-object document. */
    public static Map<String, Object> parseObjectLenient(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        try {
            return StrictJson.parseObject(text);
        } catch (IllegalArgumentException garbled) {
            return null;
        }
    }

    private StrictJsonAccess() {}
}
