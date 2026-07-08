package dev.hg.grantmint.core.entitlement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Property coverage for the {@code ent}-claim encoding: any entitlement set survives an
 * encode→decode round-trip, including feature flags, numeric limits at the extremes of the 64-bit
 * range, string entitlements, the {@code -1} unlimited sentinel, and the empty set. The pair is the
 * contract every cross-language verifier must match — see docs/features/ENTITLEMENTS.md.
 */
class EntitlementSetPropertyTest {

    /** decode(encode(set)) == set, and encoding is stable, for any mix of entitlement kinds. */
    @Property(tries = 1000)
    void encodeDecodeRoundTripsByValue(@ForAll("entitlementLists") List<Entitlement> items) {
        EntitlementSet original = EntitlementSet.of(items);

        EntitlementSet roundTripped = EntitlementSet.decode(original.encode());

        assertThat(roundTripped).isEqualTo(original);
        assertThat(roundTripped.encode()).isEqualTo(original.encode());
    }

    /** Numeric limits at the integer extremes round-trip without overflow or truncation. */
    @Property(tries = 500)
    void limitExtremesSurvive(@ForAll("keys") String key, @ForAll long value) {
        EntitlementSet set = EntitlementSet.of(Entitlement.limit(key, value));

        EntitlementSet decoded = EntitlementSet.decode(set.encode());

        assertThat(decoded.limit(key, Long.MIN_VALUE)).isEqualTo(value);
    }

    /**
     * decode is a wire-side gate: any key not already in canonical {@code ^[a-z][a-z0-9_]{0,62}$}
     * form is rejected, never normalized — normalizing would let two JSON-distinct keys collapse
     * last-wins in this SDK while staying distinct in a verifier that does not normalize.
     */
    @Property(tries = 500)
    void decodeRejectsNonCanonicalKeys(@ForAll("nonCanonicalKeys") String badKey, @ForAll long value) {
        assertThatThrownBy(() -> EntitlementSet.decode(Map.of(badKey, value)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("canonical");
    }

    /** Every key the SDK itself encodes is canonical, so decode always accepts encode's output. */
    @Property(tries = 500)
    void encodedKeysAreAlwaysCanonical(@ForAll("entitlementLists") List<Entitlement> items) {
        EntitlementSet original = EntitlementSet.of(items);
        for (String key : original.encode().keySet()) {
            assertThat(EntitlementKey.isCanonical(key))
                    .as("encoded key '%s'", key)
                    .isTrue();
        }
    }

    // ---- arbitraries ----

    @Provide
    Arbitrary<String> keys() {
        // Mixed case exercises the Locale.ROOT key normalization on the round trip.
        return Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(8);
    }

    @Provide
    Arbitrary<String> nonCanonicalKeys() {
        Arbitrary<String> lower =
                Arbitraries.strings().withCharRange('a', 'z').ofMinLength(1).ofMaxLength(8);
        return Arbitraries.oneOf(
                // Any uppercase character breaks the grammar (the normalization-collision class).
                lower.map(k -> k.toUpperCase(Locale.ROOT)),
                // Leading digit / underscore / whitespace, an inner dash, and an over-long key.
                lower.map(k -> "9" + k),
                lower.map(k -> "_" + k),
                lower.map(k -> " " + k),
                lower.map(k -> k + "-x"),
                lower.map(k -> k + "a".repeat(64)));
    }

    @Provide
    Arbitrary<List<Entitlement>> entitlementLists() {
        Arbitrary<String> keys = keys();
        Arbitrary<Entitlement> flags =
                Combinators.combine(keys, Arbitraries.of(true, false)).as(Entitlement::flag);
        Arbitrary<Long> limitValues =
                Arbitraries.oneOf(Arbitraries.longs(), Arbitraries.of(-1L, 0L, 1L, Long.MAX_VALUE, Long.MIN_VALUE));
        Arbitrary<Entitlement> limits = Combinators.combine(keys, limitValues).as(Entitlement::limit);
        Arbitrary<Entitlement> strings =
                Combinators.combine(keys, Arbitraries.strings().ofMaxLength(12)).as(Entitlement::string);
        Arbitrary<Entitlement> any = Arbitraries.oneOf(flags, limits, strings);
        return any.list().ofMaxSize(10); // ofMaxSize includes the empty list, covering the empty set
    }
}
