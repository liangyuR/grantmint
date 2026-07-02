package dev.hg.grantmint.core.codec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import org.junit.jupiter.api.Test;

class CanonicalJsonTest {

    @Test
    void sortsKeysByCodePointWithNoWhitespace() {
        Map<String, Object> unordered = new LinkedHashMap<>();
        unordered.put("seat", 2);
        unordered.put("con", Map.of("seats", 2, "nodeLocked", true));
        unordered.put("exp", 1782666000L);

        String json = CanonicalJson.serializeToString(unordered);
        assertThat(json).isEqualTo("{\"con\":{\"nodeLocked\":true,\"seats\":2},\"exp\":1782666000,\"seat\":2}");
    }

    @Test
    void escapesQuoteBackslashNewlineButNotSlash() {
        // Input: a " b \ c <newline> d e / f  — only ", \, and the newline are escaped.
        String input = "a\"b\\c\nde/f";
        String json = CanonicalJson.serializeToString(Map.of("k", input));
        assertThat(json).isEqualTo("{\"k\":\"a\\\"b\\\\c\\nde/f\"}");
    }

    @Test
    void escapesControlCharactersAsUnicode() {
        String input = "x" + ((char) 0x01) + "y";
        String json = CanonicalJson.serializeToString(Map.of("k", input));
        assertThat(json).isEqualTo("{\"k\":\"x" + "\\u0001" + "y\"}");
        // And it parses back to the original control character.
        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = (Map<String, Object>) CanonicalJson.parse(json);
        assertThat(parsed.get("k")).isEqualTo(input);
    }

    @Test
    void emitsNullAndIntegersWithoutExponent() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("a", null);
        map.put("b", 0L);
        map.put("c", -42L);
        assertThat(CanonicalJson.serializeToString(map)).isEqualTo("{\"a\":null,\"b\":0,\"c\":-42}");
    }

    @Test
    void rejectsFloatingPoint() {
        assertThatThrownBy(() -> CanonicalJson.serialize(Map.of("x", 1.5)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void parsesNestedStructures() {
        Object parsed = CanonicalJson.parse("{\"a\":[1,2,{\"b\":true}],\"c\":\"x\"}");
        assertThat(parsed).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) parsed;
        assertThat(map.get("a")).isEqualTo(List.of(1L, 2L, Map.of("b", true)));
        assertThat(map.get("c")).isEqualTo("x");
    }

    @Test
    void parseRejectsTrailingGarbage() {
        assertThatThrownBy(() -> CanonicalJson.parse("{} junk")).isInstanceOf(JsonParseException.class);
    }

    @Test
    void parseRejectsDuplicateObjectKeys() {
        // Duplicates are undefined in JSON and resolve differently across verifiers; rejecting them
        // keeps claim interpretation identical across the Java/Swift/Go SDKs.
        assertThatThrownBy(() -> CanonicalJson.parse("{\"a\":1,\"a\":2}"))
                .isInstanceOf(JsonParseException.class)
                .hasMessageContaining("Duplicate object key 'a'");
    }

    @Test
    void parseRejectsDuplicateKeysEvenWhenAValueIsNull() {
        // containsKey (not put's return) must be used so a legitimate null value is still caught as
        // a duplicate rather than mistaken for an absent key.
        assertThatThrownBy(() -> CanonicalJson.parse("{\"a\":null,\"a\":1}"))
                .isInstanceOf(JsonParseException.class)
                .hasMessageContaining("Duplicate object key 'a'");
    }

    @Test
    void parseRejectsDuplicateKeysInNestedObject() {
        assertThatThrownBy(() -> CanonicalJson.parse("{\"outer\":{\"b\":1,\"b\":2}}"))
                .isInstanceOf(JsonParseException.class)
                .hasMessageContaining("Duplicate object key 'b'");
    }

    @Test
    void parsesWellFormedIntegers() {
        assertThat(CanonicalJson.parse("0")).isEqualTo(0L);
        assertThat(CanonicalJson.parse("-0")).isEqualTo(0L);
        assertThat(CanonicalJson.parse("-42")).isEqualTo(-42L);
        assertThat(CanonicalJson.parse("10")).isEqualTo(10L);
        assertThat(CanonicalJson.parse("1782666000")).isEqualTo(1782666000L);
        assertThat(CanonicalJson.parse(Long.toString(Long.MAX_VALUE))).isEqualTo(Long.MAX_VALUE);
        assertThat(CanonicalJson.parse(Long.toString(Long.MIN_VALUE))).isEqualTo(Long.MIN_VALUE);
    }

    @Test
    void parseRejectsNonIntegerAndOversizedNumbers() {
        // Canonical JSON is integer-only within signed 64-bit: the writer never emits a fraction, an
        // exponent, or a wider integer, so the reader treats all of them as malformed — keeping this
        // lexer exactly as strict as the starter's StrictJson (cross-verifier parity).
        for (String rejected : List.of(
                "0.5",
                "-0.5",
                "1e3",
                "1E+2",
                "2.5e-1",
                "9223372036854775808", // Long.MAX_VALUE + 1
                "-9223372036854775809", // Long.MIN_VALUE - 1
                "123456789012345678901234567890")) {
            assertThatThrownBy(() -> CanonicalJson.parse(rejected))
                    .as("parsing '%s'", rejected)
                    .isInstanceOf(JsonParseException.class);
        }
    }

    @Test
    void writesLongRangeBigIntegerButRejectsWider() {
        // BigInteger values are honored only while they fit the cross-language int64 contract; a
        // wider integer would mint a token every peer verifier must refuse, so writing one fails.
        assertThat(CanonicalJson.serializeToString(Map.of("x", java.math.BigInteger.valueOf(Long.MAX_VALUE))))
                .isEqualTo("{\"x\":9223372036854775807}");
        assertThatThrownBy(() -> CanonicalJson.serialize(Map.of("x", new java.math.BigInteger("9223372036854775808"))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("64-bit");
    }

    @Test
    void parseRejectsMalformedNumbersAsJsonParseException() {
        // Each violates the strict RFC 8259 number grammar and must surface as a JsonParseException —
        // never a leaked raw NumberFormatException — matching the stricter Swift/Go JSON parsers so a
        // hand-crafted token is rejected identically across every SDK.
        for (String malformed : List.of(
                "+5", // leading plus
                "01", // leading zero
                "-01", // leading zero after sign
                "00", // leading zero
                ".5", // bare fraction, no integer part
                "-.5", // sign then bare fraction
                "1.", // missing fraction digits
                "1e", // missing exponent digits
                "1e+", // missing exponent digits after sign
                "-", // sign only
                "1.2.3", // two fraction points
                "1e2e3")) { // two exponents
            assertThatThrownBy(() -> CanonicalJson.parse(malformed))
                    .as("parsing '%s'", malformed)
                    .isInstanceOf(JsonParseException.class);
        }
    }

    @Test
    void rejectsMalformedNumbersNestedInStructures() {
        assertThatThrownBy(() -> CanonicalJson.parse("{\"a\":01}")).isInstanceOf(JsonParseException.class);
        assertThatThrownBy(() -> CanonicalJson.parse("[1,+2]")).isInstanceOf(JsonParseException.class);
        assertThatThrownBy(() -> CanonicalJson.parse("{\"a\":1.}")).isInstanceOf(JsonParseException.class);
    }

    /**
     * Every {@code long} serializes to a strict integer literal that parses back to the same value —
     * the tightened number lexer accepts all well-formed integers and regresses none.
     */
    @Property(tries = 1000)
    void everyLongRoundTripsThroughStrictNumberLexer(@ForAll long value) {
        assertThat(CanonicalJson.parse(Long.toString(value))).isEqualTo(value);
    }

    /**
     * Task M1: canonical encode/decode round-trips byte-for-byte. Serializing, parsing, and
     * re-serializing any supported value yields identical bytes — the property the signing input
     * relies on.
     */
    @Property(tries = 1000)
    void canonicalFormRoundTripsByteForByte(@ForAll("jsonValues") Object value) {
        byte[] first = CanonicalJson.serialize(value);
        Object parsed = CanonicalJson.parse(first);
        byte[] second = CanonicalJson.serialize(parsed);
        assertThat(second).isEqualTo(first);
        // And the canonical bytes are valid UTF-8 that re-parses to the same structure.
        assertThat(CanonicalJson.parse(new String(first, StandardCharsets.UTF_8)))
                .isEqualTo(parsed);
    }

    @Provide
    Arbitrary<Object> jsonValues() {
        return jsonValue(3);
    }

    private Arbitrary<Object> jsonValue(int depth) {
        // Range incl. control chars, '"', '\', '/' to exercise escaping; capped below U+0080 so every
        // generated string is valid (surrogate-free) UTF-8.
        Arbitrary<Object> strings = Arbitraries.strings()
                .withCharRange((char) 0x01, (char) 0x7e)
                .ofMaxLength(8)
                .map(s -> (Object) s);
        Arbitrary<Object> longs = Arbitraries.longs().map(l -> (Object) l);
        Arbitrary<Object> bools = Arbitraries.of(true, false).map(b -> (Object) b);
        Arbitrary<Object> nulls = Arbitraries.just(null);
        Arbitrary<Object> scalars = Arbitraries.oneOf(strings, longs, bools, nulls);
        if (depth == 0) {
            return scalars;
        }
        Arbitrary<Object> lists = jsonValue(depth - 1).list().ofMaxSize(3).map(l -> (Object) l);
        Arbitrary<Object> maps = Arbitraries.maps(
                        Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(6), jsonValue(depth - 1))
                .ofMaxSize(3)
                .map(m -> (Object) m);
        return Arbitraries.oneOf(scalars, lists, maps);
    }
}
