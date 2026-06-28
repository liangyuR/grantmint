package dev.hg.grantmint.core.codec;

/**
 * Thrown when a token segment is not well-formed JSON. During verification this is treated as a
 * malformed (untrusted) token, never as a server fault.
 */
public final class JsonParseException extends RuntimeException {

    public JsonParseException(String message) {
        super(message);
    }
}
