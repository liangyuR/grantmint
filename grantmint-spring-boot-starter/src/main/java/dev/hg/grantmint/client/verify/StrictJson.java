package dev.hg.grantmint.client.verify;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal, strict JSON reader for verified token segments — deliberately less forgiving than a
 * general-purpose parser, because verifiers in every language must read the same signed bytes
 * identically or refuse (docs/testing/CROSS_VERIFIER_FIXTURES.md):
 *
 * <ul>
 *   <li><b>Duplicate object keys are an error</b>, never first-wins or last-wins.
 *   <li><b>Numbers are integers only</b> — no fraction, no exponent, no leading zeros, and they must
 *       fit a signed 64-bit long. Canonical JSON never emits anything else.
 *   <li>No trailing content after the top-level value; strings take only the standard escapes.
 * </ul>
 *
 * <p>Values map to {@code LinkedHashMap<String,Object>} / {@code List<Object>} / {@code String} /
 * {@code Long} / {@code Boolean} / {@code null}. Fresh Apache-2.0 code (no AGPL {@code
 * grantmint-core} on this classpath); parity with the reference codec is pinned by fixtures.
 */
final class StrictJson {

    private final String text;
    private int pos;

    private StrictJson(String text) {
        this.text = text;
    }

    /** Parse a complete JSON document that must be a single object. */
    static Map<String, Object> parseObject(String text) {
        StrictJson parser = new StrictJson(text);
        parser.skipWhitespace();
        Object value = parser.parseValue();
        parser.skipWhitespace();
        if (parser.pos != text.length()) {
            throw new IllegalArgumentException("trailing content after JSON value");
        }
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("expected a JSON object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> object = (Map<String, Object>) value;
        return object;
    }

    private Object parseValue() {
        if (pos >= text.length()) {
            throw new IllegalArgumentException("unexpected end of JSON");
        }
        char c = text.charAt(pos);
        return switch (c) {
            case '{' -> parseObjectValue();
            case '[' -> parseArray();
            case '"' -> parseString();
            case 't' -> parseLiteral("true", Boolean.TRUE);
            case 'f' -> parseLiteral("false", Boolean.FALSE);
            case 'n' -> parseLiteral("null", null);
            default -> parseNumber();
        };
    }

    private Map<String, Object> parseObjectValue() {
        expect('{');
        Map<String, Object> object = new LinkedHashMap<>();
        skipWhitespace();
        if (peek() == '}') {
            pos++;
            return object;
        }
        while (true) {
            skipWhitespace();
            String key = parseString();
            if (object.containsKey(key)) {
                // Undefined in JSON, divergent across parsers — pinned as an error so every
                // language reads identical bytes identically.
                throw new IllegalArgumentException("duplicate object key: " + key);
            }
            skipWhitespace();
            expect(':');
            skipWhitespace();
            object.put(key, parseValue());
            skipWhitespace();
            char next = next();
            if (next == '}') {
                return object;
            }
            if (next != ',') {
                throw new IllegalArgumentException("expected ',' or '}' in object");
            }
        }
    }

    private List<Object> parseArray() {
        expect('[');
        List<Object> array = new ArrayList<>();
        skipWhitespace();
        if (peek() == ']') {
            pos++;
            return array;
        }
        while (true) {
            skipWhitespace();
            array.add(parseValue());
            skipWhitespace();
            char next = next();
            if (next == ']') {
                return array;
            }
            if (next != ',') {
                throw new IllegalArgumentException("expected ',' or ']' in array");
            }
        }
    }

    private String parseString() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= text.length()) {
                throw new IllegalArgumentException("unterminated string");
            }
            char c = text.charAt(pos++);
            if (c == '"') {
                return sb.toString();
            }
            if (c < 0x20) {
                throw new IllegalArgumentException("unescaped control character in string");
            }
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            if (pos >= text.length()) {
                throw new IllegalArgumentException("unterminated escape");
            }
            char escape = text.charAt(pos++);
            switch (escape) {
                case '"' -> sb.append('"');
                case '\\' -> sb.append('\\');
                case '/' -> sb.append('/');
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                case 'u' -> {
                    if (pos + 4 > text.length()) {
                        throw new IllegalArgumentException("truncated unicode escape");
                    }
                    sb.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                    pos += 4;
                }
                default -> throw new IllegalArgumentException("invalid escape: \\" + escape);
            }
        }
    }

    private Long parseNumber() {
        int start = pos;
        if (peek() == '-') {
            pos++;
        }
        if (pos >= text.length() || !isDigit(text.charAt(pos))) {
            throw new IllegalArgumentException("invalid number");
        }
        // Integer-only lexer with the canonical no-leading-zero rule ("0" alone is fine).
        if (text.charAt(pos) == '0' && pos + 1 < text.length() && isDigit(text.charAt(pos + 1))) {
            throw new IllegalArgumentException("leading zero in number");
        }
        while (pos < text.length() && isDigit(text.charAt(pos))) {
            pos++;
        }
        if (pos < text.length()) {
            char c = text.charAt(pos);
            if (c == '.' || c == 'e' || c == 'E') {
                throw new IllegalArgumentException("non-integer number in canonical JSON");
            }
        }
        try {
            return Long.parseLong(text, start, pos, 10);
        } catch (NumberFormatException overflow) {
            throw new IllegalArgumentException("integer out of 64-bit range");
        }
    }

    private Object parseLiteral(String literal, Object value) {
        if (!text.startsWith(literal, pos)) {
            throw new IllegalArgumentException("invalid JSON literal");
        }
        pos += literal.length();
        return value;
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private void skipWhitespace() {
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                pos++;
            } else {
                return;
            }
        }
    }

    private char peek() {
        if (pos >= text.length()) {
            throw new IllegalArgumentException("unexpected end of JSON");
        }
        return text.charAt(pos);
    }

    private char next() {
        char c = peek();
        pos++;
        return c;
    }

    private void expect(char expected) {
        if (next() != expected) {
            throw new IllegalArgumentException("expected '" + expected + "'");
        }
    }
}
