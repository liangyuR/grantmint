package dev.hg.grantmint.core.token;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.entitlement.Entitlement;
import dev.hg.grantmint.core.entitlement.EntitlementSet;
import dev.hg.grantmint.core.time.Clock;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Assume;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.IntRange;

/**
 * The M1 correctness invariants for issuance + offline verification, expressed as jqwik properties.
 * A license that verifies when it shouldn't — or fails when it shouldn't — is a false security
 * claim, so these are first-class deliverables (see docs/testing/TESTING.md).
 */
class LicenseTokenPropertyTest {

    private static final SecureRandom RNG = new SecureRandom();

    /** M1: any issued token verifies offline against its public key, and its entitlements survive. */
    @Property(tries = 2000)
    void issuedTokenVerifiesAndEntitlementsSurvive(@ForAll("validPayloads") Generated generated) {
        KeyPair keyPair = Ed25519Keys.generate(RNG);
        LicenseTokenIssuer issuer = new LicenseTokenIssuer(new Ed25519Signer(keyPair.getPrivate(), "K1"));

        String token = issuer.sign(generated.payload());
        VerificationResult result = LicenseVerifier.verifyAt(token, keyPair.getPublic(), generated.clock());

        assertThat(result.isValid())
                .as("token should verify at a time inside its validity window")
                .isTrue();
        assertThat(result.payload().entitlements())
                .isEqualTo(generated.payload().entitlements());
        assertThat(result.header().alg()).isEqualTo(TokenHeader.ALG_EDDSA);
        assertThat(result.payload().kid()).isEqualTo(generated.payload().kid());
    }

    /**
     * M1 (audit remediation): product binding is exact. Any issued token verifies when the expected
     * product matches its {@code prd} claim, and is rejected as {@link FailureReason#WRONG_PRODUCT}
     * when it does not — the cross-product acceptance guard for single-key-pair, multi-product setups.
     */
    @Property(tries = 2000)
    void productBindingAcceptsMatchAndRejectsMismatch(@ForAll("validPayloads") Generated generated) {
        KeyPair keyPair = Ed25519Keys.generate(RNG);
        LicenseTokenIssuer issuer = new LicenseTokenIssuer(new Ed25519Signer(keyPair.getPrivate(), "K1"));
        String token = issuer.sign(generated.payload());
        String prd = generated.payload().prd();

        VerificationResult match = LicenseVerifier.verifyAt(token, keyPair.getPublic(), generated.clock(), prd);
        assertThat(match.isValid())
                .as("token must verify when the expected product matches its prd claim")
                .isTrue();

        VerificationResult mismatch =
                LicenseVerifier.verifyAt(token, keyPair.getPublic(), generated.clock(), prd + "_other");
        assertThat(mismatch.reason())
                .as("token for product %s must be rejected for a different product", prd)
                .isEqualTo(FailureReason.WRONG_PRODUCT);
    }

    /**
     * M1: any single-character tampering of the signed content (header or payload) fails
     * verification. Every char in segments A/B is part of the ASCII signing input, so changing any
     * one breaks the Ed25519 signature.
     *
     * <p>Note: the signature segment itself is excluded here because its failure mode is different,
     * not because it is tolerated — corrupting significant bits is covered by
     * {@link #corruptingSignatureSignificantBitsFails}, and flipping the final char's 4 redundant
     * trailing bits (an alternate encoding of the <em>same</em> signature, which pre-M6-audit code
     * accepted) is rejected as non-canonical by {@link #nonCanonicalSignatureSpellingIsMalformed}.
     */
    @Property(tries = 2000)
    void tamperingSignedContentFails(@ForAll("validPayloads") Generated generated, @ForAll int rawIndex) {
        KeyPair keyPair = Ed25519Keys.generate(RNG);
        LicenseTokenIssuer issuer = new LicenseTokenIssuer(new Ed25519Signer(keyPair.getPrivate(), "K1"));
        String token = issuer.sign(generated.payload());

        int signatureStart = token.lastIndexOf('.'); // tamper only within header + payload + first dot
        int pos = Math.floorMod(rawIndex, signatureStart);
        char original = token.charAt(pos);
        Assume.that(original != '.'); // changing a separator re-tests structure; covered by unit tests
        char replacement = original == 'A' ? 'B' : 'A'; // both valid base64url, always different
        String tampered = token.substring(0, pos) + replacement + token.substring(pos + 1);

        VerificationResult result = LicenseVerifier.verifyAt(tampered, keyPair.getPublic(), generated.clock());
        assertThat(result.isValid())
                .as("flipping char at %d (%s->%s) must invalidate the token", pos, original, replacement)
                .isFalse();
    }

    /** M1: corrupting the significant bits of the signature fails verification (forged signature). */
    @Property(tries = 1000)
    void corruptingSignatureSignificantBitsFails(@ForAll("validPayloads") Generated generated) {
        KeyPair keyPair = Ed25519Keys.generate(RNG);
        LicenseTokenIssuer issuer = new LicenseTokenIssuer(new Ed25519Signer(keyPair.getPrivate(), "K1"));
        String token = issuer.sign(generated.payload());

        // The first signature char encodes the top 6 (always significant) bits of byte 0.
        int firstSignatureChar = token.lastIndexOf('.') + 1;
        char original = token.charAt(firstSignatureChar);
        char replacement = original == 'A' ? 'B' : 'A';
        String tampered =
                token.substring(0, firstSignatureChar) + replacement + token.substring(firstSignatureChar + 1);

        VerificationResult result = LicenseVerifier.verifyAt(tampered, keyPair.getPublic(), generated.clock());
        assertThat(result.isValid()).isFalse();
    }

    /**
     * M6–M10 audit remediation: canonicality of the signature segment. A 64-byte signature is 86
     * base64url chars whose final char carries 4 unused trailing bits, so 15 alternate spellings
     * decode to the SAME signature bytes — and the segment is not covered by the signing input, so
     * the signature check alone cannot tell them apart. Accepting any of them would let one license
     * circulate as 16 distinct token strings and split the verdict against the starter/Swift/Go
     * verifiers (LICENSE_TOKEN_FORMAT.md pins one text form per byte string). Every non-canonical
     * spelling must be MALFORMED for every issuable token; the canonical spelling must stay valid.
     */
    @Property(tries = 1000)
    void nonCanonicalSignatureSpellingIsMalformed(
            @ForAll("validPayloads") Generated generated, @ForAll @IntRange(min = 1, max = 15) int trailingBits) {
        KeyPair keyPair = Ed25519Keys.generate(RNG);
        LicenseTokenIssuer issuer = new LicenseTokenIssuer(new Ed25519Signer(keyPair.getPrivate(), "K1"));
        String token = issuer.sign(generated.payload());
        assertThat(LicenseVerifier.verifyAt(token, keyPair.getPublic(), generated.clock())
                        .isValid())
                .isTrue();

        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int lastValue = alphabet.indexOf(token.charAt(token.length() - 1));
        assertThat(lastValue % 16)
                .as("canonical final signature char has zero trailing bits")
                .isZero();
        String nonCanonical = token.substring(0, token.length() - 1) + alphabet.charAt(lastValue | trailingBits);

        VerificationResult result = LicenseVerifier.verifyAt(nonCanonical, keyPair.getPublic(), generated.clock());
        assertThat(result.reason())
                .as("alternate signature spelling (trailing bits %d) must be malformed", trailingBits)
                .isEqualTo(FailureReason.MALFORMED);
    }

    /** M1: a token fails at/after exp; a not-yet-valid token fails before nbf; valid in between. */
    @Property(tries = 1000)
    void expiryAndNotBeforeBoundaries(
            @ForAll long iatSeed, @ForAll long gapSeed, @ForAll("entitlementSets") EntitlementSet ent) {
        long iat = 1_000_000_000L + Math.floorMod(iatSeed, 500_000_000L);
        long gap = 2L + Math.floorMod(gapSeed, 1_000_000_000L); // ensure exp is at least nbf + 2
        long nbf = iat;
        long exp = iat + gap;

        KeyPair keyPair = Ed25519Keys.generate(RNG);
        LicenseTokenIssuer issuer = new LicenseTokenIssuer(new Ed25519Signer(keyPair.getPrivate(), "K1"));
        TokenPayload payload = payload(iat, nbf, exp, ent);
        String token = issuer.sign(payload);

        assertThat(verifyAt(token, keyPair, exp).reason()).isEqualTo(FailureReason.EXPIRED);
        assertThat(verifyAt(token, keyPair, exp + 1).reason()).isEqualTo(FailureReason.EXPIRED);
        assertThat(verifyAt(token, keyPair, nbf - 1).reason()).isEqualTo(FailureReason.NOT_YET_VALID);
        assertThat(verifyAt(token, keyPair, nbf).isValid()).isTrue();
        assertThat(verifyAt(token, keyPair, exp - 1).isValid()).isTrue();
    }

    private static VerificationResult verifyAt(String token, KeyPair keyPair, long epochSecond) {
        return LicenseVerifier.verifyAt(token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(epochSecond)));
    }

    private static TokenPayload payload(long iat, Long nbf, Long exp, EntitlementSet ent) {
        return new TokenPayload(
                TokenPayload.CURRENT_VERSION,
                "lic_test",
                "K7P2-9QXM-4T1A",
                "prod_acme_notes",
                "pol_pro_annual",
                new Holder("Jane Doe", "jane@example.com"),
                iat,
                nbf,
                exp,
                ent,
                null,
                null);
    }

    // ---- arbitraries ----

    /** A payload plus a clock fixed at a time inside its validity window. */
    record Generated(TokenPayload payload, Clock clock) {}

    @Provide
    Arbitrary<Generated> validPayloads() {
        Arbitrary<String> idents =
                Arbitraries.strings().withCharRange('a', 'z').ofMinLength(1).ofMaxLength(10);
        Arbitrary<Long> iats = Arbitraries.longs().between(1_000_000_000L, 1_500_000_000L);
        Arbitrary<Long> nbfOffsets =
                Arbitraries.oneOf(Arbitraries.just(null), Arbitraries.longs().between(0L, 100_000L));
        Arbitrary<Long> expOffsets =
                Arbitraries.oneOf(Arbitraries.just(null), Arbitraries.longs().between(1L, 1_000_000_000L));
        Arbitrary<ConSeat> conSeats = constraintsAndSeat();

        return Combinators.combine(idents, idents, iats, nbfOffsets, expOffsets, entitlementSets(), conSeats)
                .as((ident, ident2, iat, nbfOffset, expOffset, ent, conSeat) -> {
                    Long nbf = nbfOffset == null ? null : iat - nbfOffset;
                    Long exp = expOffset == null ? null : iat + expOffset;
                    TokenPayload payload = new TokenPayload(
                            TokenPayload.CURRENT_VERSION,
                            "lic_" + ident,
                            "K7P2-9QXM-4T1A",
                            "prod_" + ident,
                            "pol_" + ident2,
                            new Holder(ident, ident + "@example.com"),
                            iat,
                            nbf,
                            exp,
                            ent,
                            conSeat.constraints(),
                            conSeat.seat());
                    // now == iat is inside the window: nbf <= iat (offset >= 0) and iat < exp (offset >= 1).
                    return new Generated(payload, Clock.fixed(Instant.ofEpochSecond(iat)));
                });
    }

    @Provide
    Arbitrary<EntitlementSet> entitlementSets() {
        Arbitrary<String> keys =
                Arbitraries.strings().withCharRange('a', 'z').ofMinLength(1).ofMaxLength(8);
        Arbitrary<Entitlement> flags =
                Combinators.combine(keys, Arbitraries.of(true, false)).as(Entitlement::flag);
        Arbitrary<Entitlement> limits = Combinators.combine(
                        keys, Arbitraries.longs().between(-1L, 1_000_000L))
                .as(Entitlement::limit);
        Arbitrary<Entitlement> strings = Combinators.combine(
                        keys, Arbitraries.strings().alpha().ofMaxLength(6))
                .as(Entitlement::string);
        Arbitrary<Entitlement> any = Arbitraries.oneOf(flags, limits, strings);
        return any.list().ofMaxSize(6).map(EntitlementSet::of);
    }

    private record ConSeat(Map<String, Object> constraints, Integer seat) {}

    private Arbitrary<ConSeat> constraintsAndSeat() {
        Arbitrary<Integer> seatCounts = Arbitraries.integers().between(1, 100);
        Arbitrary<Map<String, Object>> cons = Combinators.combine(seatCounts, Arbitraries.of(true, false))
                .as((seats, nodeLocked) -> {
                    Map<String, Object> map = new LinkedHashMap<>();
                    map.put("seats", seats.longValue());
                    map.put("nodeLocked", nodeLocked);
                    return map;
                });
        Arbitrary<Map<String, Object>> consOpt = Arbitraries.oneOf(Arbitraries.just(null), cons);
        Arbitrary<Integer> seatOpt = Arbitraries.oneOf(Arbitraries.just(null), seatCounts);
        return Combinators.combine(consOpt, seatOpt).as(ConSeat::new);
    }
}
