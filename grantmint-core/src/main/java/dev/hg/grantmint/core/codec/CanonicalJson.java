package dev.hg.grantmint.core.codec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * The canonical JSON form Ed25519 signs over — and its inverse.
 *
 * <p>Ed25519 signs <em>bytes</em>, so the signer and every verifier (Java, Swift, Go) must serialize
 * a payload to the <strong>exact same bytes</strong>. This class pins that form so a token signed by
 * the server verifies byte-for-byte everywhere:
 *
 * <ul>
 *   <li>UTF-8 encoding;
 *   <li>object keys sorted lexicographically by Unicode code point;
 *   <li>no insignificant whitespace ({@code "k":v}, entries joined by {@code ,});
 *   <li>integers only — no exponents, no {@code +0}/{@code -0}; floating point is rejected outright
 *       (our claims are epoch seconds and integer limits, and floats have no canonical text form);
 *   <li>minimal string escaping (only what JSON requires).
 * </ul>
 *
 * <p>The accepted Java value model is: {@link Map}{@code <String, ?>}, {@link List}, {@link String},
 * {@link Boolean}, {@link Integer}/{@link Long}/{@link BigInteger}, and {@code null}.
 *
 * <p><strong>Verification rule:</strong> a verifier checks the signature against the <em>received</em>
 * payload bytes — never a re-serialization. {@link #parse} exists to <em>read</em> claims after the
 * signature has already been confirmed, not to recompute the signing input.
 *
 * <p>See docs/features/LICENSE_TOKEN_FORMAT.md (Canonical JSON).
 */
public final class CanonicalJson {

    private CanonicalJson() {}

    /** Serialize a value to canonical UTF-8 JSON bytes. */
    public static byte[] serialize(Object value) {
        StringBuilder out = new StringBuilder(256);
        write(value, out);
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** Serialize a value to a canonical JSON string. */
    public static String serializeToString(Object value) {
        StringBuilder out = new StringBuilder(256);
        write(value, out);
        return out.toString();
    }

    /** Parse JSON bytes (UTF-8) into the Java value model. */
    public static Object parse(byte[] json) {
        Objects.requireNonNull(json, "json");
        return parse(new String(json, StandardCharsets.UTF_8));
    }

    /** Parse a JSON string into the Java value model. */
    public static Object parse(String json) {
        Objects.requireNonNull(json, "json");
        Cursor cursor = new Cursor(json);
        cursor.skipWhitespace();
        Object value = cursor.readValue();
        cursor.skipWhitespace();
        if (!cursor.atEnd()) {
            throw new JsonParseException("Trailing content after JSON value at index " + cursor.index);
        }
        return value;
    }

    // ---- serialization ----

    private static void write(Object value, StringBuilder out) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof Map<?, ?> map) {
            writeObject(map, out);
        } else if (value instanceof List<?> list) {
            writeArray(list, out);
        } else if (value instanceof String s) {
            writeString(s, out);
        } else if (value instanceof Boolean b) {
            out.append(b.booleanValue() ? "true" : "false");
        } else if (value instanceof Integer || value instanceof Long || value instanceof BigInteger) {
            out.append(value.toString());
        } else if (value instanceof Double || value instanceof Float) {
            throw new IllegalArgumentException("Floating point is not allowed in canonical JSON: " + value);
        } else {
            throw new IllegalArgumentException("Unsupported value type for canonical JSON: "
                    + value.getClass().getName());
        }
    }

    private static void writeObject(Map<?, ?> map, StringBuilder out) {
        // Sort keys by Unicode code point. A TreeMap with the code-point comparator gives a stable,
        // language-agnostic ordering identical to what the Swift/Go verifiers must reproduce.
        TreeMap<String, Object> sorted = new TreeMap<>(CanonicalJson::compareByCodePoint);
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IllegalArgumentException("Canonical JSON object keys must be strings");
            }
            sorted.put(key, entry.getValue());
        }
        out.append('{');
        boolean first = true;
        for (Map.Entry<String, Object> entry : sorted.entrySet()) {
            if (!first) {
                out.append(',');
            }
            first = false;
            writeString(entry.getKey(), out);
            out.append(':');
            write(entry.getValue(), out);
        }
        out.append('}');
    }

    private static void writeArray(List<?> list, StringBuilder out) {
        out.append('[');
        boolean first = true;
        for (Object element : list) {
            if (!first) {
                out.append(',');
            }
            first = false;
            write(element, out);
        }
        out.append(']');
    }

    private static void writeString(String s, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\t' -> out.append("\\t");
                case '\n' -> out.append("\\n");
                case '\f' -> out.append("\\f");
                case '\r' -> out.append("\\r");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        // Non-ASCII passes through and becomes UTF-8 at encode time.
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    static int compareByCodePoint(String a, String b) {
        int i = 0;
        int j = 0;
        while (i < a.length() && j < b.length()) {
            int ca = a.codePointAt(i);
            int cb = b.codePointAt(j);
            if (ca != cb) {
                return Integer.compare(ca, cb);
            }
            i += Character.charCount(ca);
            j += Character.charCount(cb);
        }
        return Integer.compare(a.length() - i, b.length() - j);
    }

    // ---- parsing ----

    private static final class Cursor {
        private final String s;
        private int index;

        Cursor(String s) {
            this.s = s;
        }

        boolean atEnd() {
            return index >= s.length();
        }

        void skipWhitespace() {
            while (index < s.length()) {
                char c = s.charAt(index);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    index++;
                } else {
                    break;
                }
            }
        }

        Object readValue() {
            if (atEnd()) {
                throw new JsonParseException("Unexpected end of JSON");
            }
            char c = s.charAt(index);
            return switch (c) {
                case '{' -> readObject();
                case '[' -> readArray();
                case '"' -> readString();
                case 't', 'f' -> readBoolean();
                case 'n' -> readNull();
                default -> readNumber();
            };
        }

        private Map<String, Object> readObject() {
            expect('{');
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (peek() == '}') {
                index++;
                return map;
            }
            while (true) {
                skipWhitespace();
                if (peek() != '"') {
                    throw new JsonParseException("Expected string key at index " + index);
                }
                String key = readString();
                skipWhitespace();
                expect(':');
                skipWhitespace();
                map.put(key, readValue());
                skipWhitespace();
                char c = next();
                if (c == '}') {
                    return map;
                }
                if (c != ',') {
                    throw new JsonParseException("Expected ',' or '}' at index " + (index - 1));
                }
            }
        }

        private List<Object> readArray() {
            expect('[');
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (peek() == ']') {
                index++;
                return list;
            }
            while (true) {
                skipWhitespace();
                list.add(readValue());
                skipWhitespace();
                char c = next();
                if (c == ']') {
                    return list;
                }
                if (c != ',') {
                    throw new JsonParseException("Expected ',' or ']' at index " + (index - 1));
                }
            }
        }

        private String readString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (atEnd()) {
                    throw new JsonParseException("Unterminated string");
                }
                char c = s.charAt(index++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    char esc = next();
                    switch (esc) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 't' -> sb.append('\t');
                        case 'n' -> sb.append('\n');
                        case 'f' -> sb.append('\f');
                        case 'r' -> sb.append('\r');
                        case 'u' -> sb.append(readUnicodeEscape());
                        default -> throw new JsonParseException("Invalid escape '\\" + esc + "'");
                    }
                } else if (c < 0x20) {
                    throw new JsonParseException("Unescaped control character in string at index " + (index - 1));
                } else {
                    sb.append(c);
                }
            }
        }

        private char readUnicodeEscape() {
            if (index + 4 > s.length()) {
                throw new JsonParseException("Truncated \\u escape");
            }
            int code = 0;
            for (int k = 0; k < 4; k++) {
                code = (code << 4) | hexDigit(s.charAt(index++));
            }
            return (char) code;
        }

        private int hexDigit(char c) {
            if (c >= '0' && c <= '9') {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f') {
                return c - 'a' + 10;
            }
            if (c >= 'A' && c <= 'F') {
                return c - 'A' + 10;
            }
            throw new JsonParseException("Invalid hex digit '" + c + "'");
        }

        private Boolean readBoolean() {
            if (s.startsWith("true", index)) {
                index += 4;
                return Boolean.TRUE;
            }
            if (s.startsWith("false", index)) {
                index += 5;
                return Boolean.FALSE;
            }
            throw new JsonParseException("Invalid literal at index " + index);
        }

        private Object readNull() {
            if (s.startsWith("null", index)) {
                index += 4;
                return null;
            }
            throw new JsonParseException("Invalid literal at index " + index);
        }

        private Object readNumber() {
            int start = index;
            if (peek() == '-') {
                index++;
            }
            boolean integral = true;
            while (!atEnd()) {
                char c = s.charAt(index);
                if (c >= '0' && c <= '9') {
                    index++;
                } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    integral = false;
                    index++;
                } else {
                    break;
                }
            }
            String literal = s.substring(start, index);
            if (literal.isEmpty() || "-".equals(literal)) {
                throw new JsonParseException("Invalid number at index " + start);
            }
            if (integral) {
                try {
                    return Long.parseLong(literal);
                } catch (NumberFormatException overflow) {
                    return new BigInteger(literal);
                }
            }
            return Double.parseDouble(literal);
        }

        private char peek() {
            if (atEnd()) {
                throw new JsonParseException("Unexpected end of JSON");
            }
            return s.charAt(index);
        }

        private char next() {
            if (atEnd()) {
                throw new JsonParseException("Unexpected end of JSON");
            }
            return s.charAt(index++);
        }

        private void expect(char c) {
            char actual = next();
            if (actual != c) {
                throw new JsonParseException("Expected '" + c + "' but found '" + actual + "' at index " + (index - 1));
            }
        }
    }
}
