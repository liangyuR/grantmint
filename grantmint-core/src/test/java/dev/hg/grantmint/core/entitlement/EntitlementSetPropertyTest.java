package dev.hg.grantmint.core.entitlement;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
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

    // ---- arbitraries ----

    @Provide
    Arbitrary<String> keys() {
        // Mixed case exercises the Locale.ROOT key normalization on the round trip.
        return Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(8);
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
