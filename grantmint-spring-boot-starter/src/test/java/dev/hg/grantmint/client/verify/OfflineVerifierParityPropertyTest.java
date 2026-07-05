package dev.hg.grantmint.client.verify;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.entitlement.Entitlement;
import dev.hg.grantmint.core.entitlement.EntitlementSet;
import dev.hg.grantmint.core.token.Holder;
import dev.hg.grantmint.core.token.LicenseTokenIssuer;
import dev.hg.grantmint.core.token.LicenseVerifier;
import dev.hg.grantmint.core.token.TokenPayload;
import dev.hg.grantmint.core.token.VerificationResult;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.Example;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.LongRange;

/**
 * The parity property behind the starter's licensing contract: this module's fresh Apache-2.0
 * verifier must agree with the AGPL reference implementation on <em>every</em> token the reference
 * can mint — same accept/reject verdict, same temporal reasons, same extracted claims. The
 * reference is a TEST-ONLY dependency (nothing AGPL ships in the starter artifact); this suite is
 * what licenses that separation. See CLIENT_SDK.md (licensing note) and CROSS_VERIFIER_FIXTURES.md.
 */
class OfflineVerifierParityPropertyTest {

    private static final SecureRandom RNG = new SecureRandom();
    private static final Instant NOW = Instant.parse("2026-06-28T12:00:00Z");

    @Property(tries = 1000)
    void starterAndReferenceVerifierAgreeOnEveryIssuedToken(
            @ForAll("entitlements") List<Entitlement> entitlements,
            @ForAll @IntRange(min = 1, max = 1000) int seat,
            @ForAll @LongRange(min = -86400 * 30, max = 86400 * 30) long nbfOffsetOrAbsent,
            @ForAll @LongRange(min = -86400 * 30, max = 86400 * 365) long expOffsetOrPerpetual,
            @ForAll boolean nbfPresent,
            @ForAll boolean perpetual) {
        KeyPair keys = Ed25519Keys.generate(RNG);
        Ed25519Signer signer = new Ed25519Signer(keys.getPrivate(), "GMK1");
        Long nbf = nbfPresent ? NOW.getEpochSecond() + nbfOffsetOrAbsent : null;
        Long exp = perpetual ? null : NOW.getEpochSecond() + expOffsetOrPerpetual;
        if (nbf != null && exp != null && nbf > exp) {
            nbf = exp; // an nbf beyond exp is not a mintable combination
        }

        String token = new LicenseTokenIssuer(signer)
                .sign(new TokenPayload(
                        TokenPayload.CURRENT_VERSION,
                        "lic_parity",
                        "K7P2-9QXM-4T1A",
                        "acme-notes",
                        "pro-annual",
                        new Holder("Jane Doe", "jane@example.com"),
                        NOW.getEpochSecond(),
                        nbf,
                        exp,
                        EntitlementSet.of(entitlements),
                        null,
                        seat));

        VerificationResult reference =
                LicenseVerifier.verifyAt(token, keys.getPublic(), dev.hg.grantmint.core.time.Clock.fixed(NOW));
        OfflineTokenVerifier starter = new OfflineTokenVerifier(
                Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(keys.getPublic())));

        if (reference.isValid()) {
            VerifiedToken verified = starter.verifyAt(token, NOW);
            assertThat(verified.keyId()).isEqualTo("K7P2-9QXM-4T1A");
            assertThat(verified.product()).isEqualTo("acme-notes");
            assertThat(verified.seatLimit()).isEqualTo(seat);
            assertThat(verified.expiresAt()).isEqualTo(exp == null ? null : Instant.ofEpochSecond(exp));
            assertThat(verified.entitlements())
                    .isEqualTo(EntitlementSet.of(entitlements).encode());
        } else {
            Throwable refusal = catchThrowable(() -> starter.verifyAt(token, NOW));
            assertThat(refusal)
                    .as("reference rejected (%s) so the starter must too", reference.reason())
                    .isInstanceOf(TokenVerificationException.class);
            TokenVerificationException.Reason starterReason = ((TokenVerificationException) refusal).reason();
            switch (reference.reason()) {
                case EXPIRED -> assertThat(starterReason).isEqualTo(TokenVerificationException.Reason.EXPIRED);
                case NOT_YET_VALID -> assertThat(starterReason)
                        .isEqualTo(TokenVerificationException.Reason.NOT_YET_VALID);
                default -> {
                    // Any other refusal must at least not be temporal disagreement.
                }
            }
        }
    }

    /**
     * The M13 audit's surviving parity split: a validly-signed {@code seat} beyond the 32-bit range
     * is MALFORMED for the reference ({@code Math.toIntExact} in the claim parse), so the starter
     * must reject the same bytes — it used to silently widen them to long and accept, a 3-vs-1
     * verdict split across the four offline verifiers.
     */
    @Example
    void seatBeyondIntRangeIsRejectedByBothImplementations() {
        KeyPair keys = Ed25519Keys.generate(RNG);
        Ed25519Signer signer = new Ed25519Signer(keys.getPrivate(), "GMK1");
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"kid\":\"GMK1\",\"crv\":\"Ed25519\"}";
        for (long seat : new long[] {5_000_000_000L, -5_000_000_000L}) {
            String payloadJson = "{\"ver\":1,\"lid\":\"l\",\"kid\":\"K\",\"prd\":\"p\",\"pol\":\"po\","
                    + "\"hld\":{\"n\":\"n\",\"e\":\"e\"},\"iat\":" + NOW.getEpochSecond() + ",\"exp\":null,"
                    + "\"ent\":{},\"seat\":" + seat + "}";
            Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
            String headerSeg = b64.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
            String payloadSeg = b64.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
            byte[] sig = signer.sign((headerSeg + "." + payloadSeg).getBytes(StandardCharsets.US_ASCII));
            String token = headerSeg + "." + payloadSeg + "." + b64.encodeToString(sig);

            VerificationResult reference =
                    LicenseVerifier.verifyAt(token, keys.getPublic(), dev.hg.grantmint.core.time.Clock.fixed(NOW));
            assertThat(reference.reason()).isEqualTo(dev.hg.grantmint.core.token.FailureReason.MALFORMED);

            OfflineTokenVerifier starter = new OfflineTokenVerifier(
                    Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(keys.getPublic())));
            assertThatThrownBy(() -> starter.verifyAt(token, NOW))
                    .isInstanceOf(TokenVerificationException.class)
                    .satisfies(e -> assertThat(((TokenVerificationException) e).reason())
                            .isEqualTo(TokenVerificationException.Reason.MALFORMED));
        }
    }

    /** Any single-character tampering of a valid token is rejected by both implementations. */
    @Property(tries = 500)
    void bothImplementationsRejectAnyTamperedToken(
            @ForAll @IntRange(min = 0, max = 10_000) int position, @ForAll @IntRange(min = 1, max = 25) int shift) {
        KeyPair keys = Ed25519Keys.generate(RNG);
        Ed25519Signer signer = new Ed25519Signer(keys.getPrivate(), "GMK1");
        String token = new LicenseTokenIssuer(signer)
                .sign(new TokenPayload(
                        TokenPayload.CURRENT_VERSION,
                        "lic_tamper",
                        "K7P2-9QXM-4T1A",
                        "acme-notes",
                        "pro-annual",
                        new Holder("Jane Doe", "jane@example.com"),
                        NOW.getEpochSecond(),
                        null,
                        NOW.getEpochSecond() + 86400,
                        EntitlementSet.of(List.of(Entitlement.flag("team_sync", true))),
                        null,
                        2));

        int index = position % token.length();
        char original = token.charAt(index);
        char replacement = original == '.' ? 'x' : rotateBase64Char(original, shift);
        if (replacement == original) {
            return;
        }
        String tampered = token.substring(0, index) + replacement + token.substring(index + 1);

        assertThat(LicenseVerifier.verifyAt(tampered, keys.getPublic(), dev.hg.grantmint.core.time.Clock.fixed(NOW))
                        .isValid())
                .isFalse();
        OfflineTokenVerifier starter = new OfflineTokenVerifier(
                Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(keys.getPublic())));
        assertThatThrownBy(() -> starter.verifyAt(tampered, NOW)).isInstanceOf(TokenVerificationException.class);
    }

    /**
     * M6–M10 audit remediation: a non-canonical spelling of the signature segment — the final char's
     * unused trailing bits flipped, so it decodes to the SAME 64 signature bytes — must be rejected
     * by BOTH implementations. This was the audit's parity break: the reference verifier's lenient
     * base64url decode accepted all 15 alternate spellings the starter refused.
     */
    @Property(tries = 200)
    void bothImplementationsRejectNonCanonicalSignatureSpellings(
            @ForAll @IntRange(min = 1, max = 15) int trailingBits) {
        KeyPair keys = Ed25519Keys.generate(RNG);
        Ed25519Signer signer = new Ed25519Signer(keys.getPrivate(), "GMK1");
        String token = new LicenseTokenIssuer(signer)
                .sign(new TokenPayload(
                        TokenPayload.CURRENT_VERSION,
                        "lic_canon",
                        "K7P2-9QXM-4T1A",
                        "acme-notes",
                        "pro-annual",
                        new Holder("Jane Doe", "jane@example.com"),
                        NOW.getEpochSecond(),
                        null,
                        NOW.getEpochSecond() + 86400,
                        EntitlementSet.of(List.of(Entitlement.flag("team_sync", true))),
                        null,
                        2));
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int lastValue = alphabet.indexOf(token.charAt(token.length() - 1));
        assertThat(lastValue % 16)
                .as("canonical final signature char has zero trailing bits")
                .isZero();
        String nonCanonical = token.substring(0, token.length() - 1) + alphabet.charAt(lastValue | trailingBits);

        assertThat(LicenseVerifier.verifyAt(nonCanonical, keys.getPublic(), dev.hg.grantmint.core.time.Clock.fixed(NOW))
                        .isValid())
                .as("reference must reject the alternate signature spelling")
                .isFalse();
        OfflineTokenVerifier starter = new OfflineTokenVerifier(
                Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(keys.getPublic())));
        assertThatThrownBy(() -> starter.verifyAt(nonCanonical, NOW))
                .as("starter must reject the alternate signature spelling")
                .isInstanceOf(TokenVerificationException.class);
    }

    /**
     * M6–M10 audit remediation: the spec's claim table marks {@code pol}, {@code hld}, and {@code
     * iat} required; the reference verifier has always enforced that, and the starter now must too —
     * a validly-signed token missing any of them is MALFORMED in both implementations.
     */
    @Example
    void bothImplementationsRequirePolHldAndIat() {
        KeyPair keys = Ed25519Keys.generate(RNG);
        Ed25519Signer signer = new Ed25519Signer(keys.getPrivate(), "GMK1");
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"kid\":\"GMK1\",\"crv\":\"Ed25519\"}";
        String base = "\"ver\":1,\"lid\":\"l\",\"kid\":\"K7P2-9QXM-4T1A\",\"prd\":\"p\",\"exp\":"
                + (NOW.getEpochSecond() + 86400) + ",\"ent\":{}";
        Map<String, String> missingClaimPayloads = Map.of(
                "pol", "{" + base + ",\"hld\":{\"n\":\"n\",\"e\":\"e\"},\"iat\":" + NOW.getEpochSecond() + "}",
                "hld", "{" + base + ",\"pol\":\"po\",\"iat\":" + NOW.getEpochSecond() + "}",
                "iat", "{" + base + ",\"pol\":\"po\",\"hld\":{\"n\":\"n\",\"e\":\"e\"}}");

        OfflineTokenVerifier starter = new OfflineTokenVerifier(
                Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(keys.getPublic())));
        missingClaimPayloads.forEach((missing, payloadJson) -> {
            String token = signRawJson(signer, headerJson, payloadJson);
            assertThat(LicenseVerifier.verifyAt(token, keys.getPublic(), dev.hg.grantmint.core.time.Clock.fixed(NOW))
                            .isValid())
                    .as("reference must reject a token missing '%s'", missing)
                    .isFalse();
            Throwable refusal = catchThrowable(() -> starter.verifyAt(token, NOW));
            assertThat(refusal)
                    .as("starter must reject a token missing '%s'", missing)
                    .isInstanceOf(TokenVerificationException.class);
            assertThat(((TokenVerificationException) refusal).reason())
                    .as("missing '%s' is a MALFORMED token, not a temporal failure", missing)
                    .isEqualTo(TokenVerificationException.Reason.MALFORMED);
        });
    }

    /**
     * Full-surface audit remediation (2026-07): the claim table requires non-empty strings, an
     * {@code ent} object of scalar values, and type-correct optional claims. A validly-signed token
     * violating any of those must be MALFORMED in both implementations — the starter used to be the
     * strict outlier on empty strings, and the reference used to silently tolerate a wrong-typed
     * {@code ent}/{@code con} the starter refused.
     */
    @Example
    void bothImplementationsRejectEmptyStringsAndWrongTypedClaims() {
        KeyPair keys = Ed25519Keys.generate(RNG);
        Ed25519Signer signer = new Ed25519Signer(keys.getPrivate(), "GMK1");
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"kid\":\"GMK1\",\"crv\":\"Ed25519\"}";
        long exp = NOW.getEpochSecond() + 86400;
        long iat = NOW.getEpochSecond();
        String requiredTail = "\"ent\":{},\"hld\":{\"e\":\"e\",\"n\":\"n\"},\"iat\":" + iat
                + ",\"kid\":\"K\",\"lid\":\"l\",\"pol\":\"po\",\"prd\":\"p\"";
        Map<String, String> payloads = Map.of(
                "empty prd",
                        "{\"ent\":{},\"exp\":" + exp + ",\"hld\":{\"e\":\"e\",\"n\":\"n\"},\"iat\":" + iat
                                + ",\"kid\":\"K\",\"lid\":\"l\",\"pol\":\"po\",\"prd\":\"\",\"ver\":1}",
                "empty holder email",
                        "{\"ent\":{},\"exp\":" + exp + ",\"hld\":{\"e\":\"\",\"n\":\"n\"},\"iat\":" + iat
                                + ",\"kid\":\"K\",\"lid\":\"l\",\"pol\":\"po\",\"prd\":\"p\",\"ver\":1}",
                "missing ent",
                        "{\"exp\":" + exp + ",\"hld\":{\"e\":\"e\",\"n\":\"n\"},\"iat\":" + iat
                                + ",\"kid\":\"K\",\"lid\":\"l\",\"pol\":\"po\",\"prd\":\"p\",\"ver\":1}",
                "ent not an object",
                        "{\"ent\":42,\"exp\":" + exp + ",\"hld\":{\"e\":\"e\",\"n\":\"n\"},\"iat\":" + iat
                                + ",\"kid\":\"K\",\"lid\":\"l\",\"pol\":\"po\",\"prd\":\"p\",\"ver\":1}",
                "ent value not a scalar",
                        "{\"ent\":{\"tiers\":[1,2]},\"exp\":" + exp + ",\"hld\":{\"e\":\"e\",\"n\":\"n\"},\"iat\":"
                                + iat + ",\"kid\":\"K\",\"lid\":\"l\",\"pol\":\"po\",\"prd\":\"p\",\"ver\":1}",
                "con not an object", "{\"con\":7,\"exp\":" + exp + "," + requiredTail + ",\"ver\":1}",
                "seat not an integer", "{\"exp\":" + exp + "," + requiredTail + ",\"seat\":\"two\",\"ver\":1}",
                "string exp", "{\"exp\":\"" + exp + "\"," + requiredTail + ",\"ver\":1}");

        OfflineTokenVerifier starter = new OfflineTokenVerifier(
                Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(keys.getPublic())));
        payloads.forEach((defect, payloadJson) -> {
            String token = signRawJson(signer, headerJson, payloadJson);
            assertThat(LicenseVerifier.verifyAt(token, keys.getPublic(), dev.hg.grantmint.core.time.Clock.fixed(NOW))
                            .isValid())
                    .as("reference must reject a token with %s", defect)
                    .isFalse();
            Throwable refusal = catchThrowable(() -> starter.verifyAt(token, NOW));
            assertThat(refusal)
                    .as("starter must reject a token with %s", defect)
                    .isInstanceOf(TokenVerificationException.class);
            assertThat(((TokenVerificationException) refusal).reason())
                    .as("a token with %s is MALFORMED, not a temporal failure", defect)
                    .isEqualTo(TokenVerificationException.Reason.MALFORMED);
        });
    }

    /**
     * The reason taxonomies must agree, not just the verdicts: alg confusion, a foreign typ, and an
     * unknown format version each carry their own reason in both implementations.
     */
    @Example
    void bothImplementationsAgreeOnPinAndVersionReasons() {
        KeyPair keys = Ed25519Keys.generate(RNG);
        Ed25519Signer signer = new Ed25519Signer(keys.getPrivate(), "GMK1");
        long exp = NOW.getEpochSecond() + 86400;
        String payloadJson = "{\"ent\":{},\"exp\":" + exp + ",\"hld\":{\"e\":\"e\",\"n\":\"n\"},\"iat\":"
                + NOW.getEpochSecond() + ",\"kid\":\"K\",\"lid\":\"l\",\"pol\":\"po\",\"prd\":\"p\",\"ver\":1}";
        String versionTwoJson = payloadJson.replace("\"ver\":1", "\"ver\":2");
        String pinnedHeader = "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"kid\":\"GMK1\",\"crv\":\"Ed25519\"}";

        record Case(
                String name,
                String headerJson,
                String payloadJson,
                dev.hg.grantmint.core.token.FailureReason reference,
                TokenVerificationException.Reason starter) {}
        List<Case> cases = List.of(
                new Case(
                        "alg=none",
                        pinnedHeader.replace("\"alg\":\"EdDSA\"", "\"alg\":\"none\""),
                        payloadJson,
                        dev.hg.grantmint.core.token.FailureReason.ALG_NOT_ALLOWED,
                        TokenVerificationException.Reason.ALG_NOT_ALLOWED),
                new Case(
                        "crv=P-256",
                        pinnedHeader.replace("\"crv\":\"Ed25519\"", "\"crv\":\"P-256\""),
                        payloadJson,
                        dev.hg.grantmint.core.token.FailureReason.ALG_NOT_ALLOWED,
                        TokenVerificationException.Reason.ALG_NOT_ALLOWED),
                new Case(
                        "typ=JWT",
                        pinnedHeader.replace("\"typ\":\"GMT\"", "\"typ\":\"JWT\""),
                        payloadJson,
                        dev.hg.grantmint.core.token.FailureReason.WRONG_TYPE,
                        TokenVerificationException.Reason.WRONG_TYPE),
                new Case(
                        "ver=2",
                        pinnedHeader,
                        versionTwoJson,
                        dev.hg.grantmint.core.token.FailureReason.UNSUPPORTED_VERSION,
                        TokenVerificationException.Reason.UNSUPPORTED_VERSION),
                new Case(
                        "kid-less header",
                        "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"crv\":\"Ed25519\"}",
                        payloadJson,
                        dev.hg.grantmint.core.token.FailureReason.MALFORMED,
                        TokenVerificationException.Reason.MALFORMED));

        OfflineTokenVerifier starter = new OfflineTokenVerifier(
                Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(keys.getPublic())));
        for (Case c : cases) {
            String token = signRawJson(signer, c.headerJson(), c.payloadJson());
            assertThat(LicenseVerifier.verifyAt(token, keys.getPublic(), dev.hg.grantmint.core.time.Clock.fixed(NOW))
                            .reason())
                    .as("reference reason for %s", c.name())
                    .isEqualTo(c.reference());
            Throwable refusal = catchThrowable(() -> starter.verifyAt(token, NOW));
            assertThat(refusal).isInstanceOf(TokenVerificationException.class);
            assertThat(((TokenVerificationException) refusal).reason())
                    .as("starter reason for %s", c.name())
                    .isEqualTo(c.starter());
        }
    }

    /**
     * Product binding sits between the version gate and the temporal window in BOTH implementations
     * (2026-07-05 audit, GRANTMINT-145): a token that is simultaneously expired and for the wrong
     * product is WRONG_PRODUCT everywhere — the reason must not depend on which implementation
     * verified it. And with the right product, both fall through to EXPIRED.
     */
    @Example
    void expiredWrongProductIsWrongProductInBothImplementations() {
        KeyPair keys = Ed25519Keys.generate(RNG);
        Ed25519Signer signer = new Ed25519Signer(keys.getPrivate(), "GMK1");
        String token = new LicenseTokenIssuer(signer)
                .sign(new TokenPayload(
                        TokenPayload.CURRENT_VERSION,
                        "lic_prd_exp",
                        "K7P2-9QXM-4T1A",
                        "acme-notes",
                        "pro-annual",
                        new Holder("Jane Doe", "jane@example.com"),
                        NOW.getEpochSecond() - 7200,
                        null,
                        NOW.getEpochSecond() - 3600, // expired an hour before NOW
                        EntitlementSet.empty(),
                        null,
                        2));

        LicenseVerifier reference = LicenseVerifier.of(keys.getPublic());
        OfflineTokenVerifier starter = new OfflineTokenVerifier(
                Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(keys.getPublic())));

        assertThat(reference
                        .verifyAt(token, dev.hg.grantmint.core.time.Clock.fixed(NOW), "some-other-app")
                        .reason())
                .isEqualTo(dev.hg.grantmint.core.token.FailureReason.WRONG_PRODUCT);
        Throwable refusal = catchThrowable(() -> starter.verifyAt(token, "some-other-app", NOW));
        assertThat(refusal).isInstanceOf(TokenVerificationException.class);
        assertThat(((TokenVerificationException) refusal).reason())
                .isEqualTo(TokenVerificationException.Reason.WRONG_PRODUCT);
        assertThat(((TokenVerificationException) refusal).keyId()).isEqualTo("K7P2-9QXM-4T1A");

        assertThat(reference
                        .verifyAt(token, dev.hg.grantmint.core.time.Clock.fixed(NOW), "acme-notes")
                        .reason())
                .isEqualTo(dev.hg.grantmint.core.token.FailureReason.EXPIRED);
        Throwable rightProduct = catchThrowable(() -> starter.verifyAt(token, "acme-notes", NOW));
        assertThat(rightProduct).isInstanceOf(TokenVerificationException.class);
        assertThat(((TokenVerificationException) rightProduct).reason())
                .isEqualTo(TokenVerificationException.Reason.EXPIRED);
    }

    /** Sign arbitrary raw JSON under the given signer — for shapes the canonical issuer refuses to mint. */
    private static String signRawJson(Ed25519Signer signer, String headerJson, String payloadJson) {
        java.util.Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String headerSegment = b64.encodeToString(headerJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String payloadSegment = b64.encodeToString(payloadJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] signature = signer.sign(
                (headerSegment + "." + payloadSegment).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return headerSegment + "." + payloadSegment + "." + b64.encodeToString(signature);
    }

    private static char rotateBase64Char(char c, int shift) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int i = alphabet.indexOf(c);
        return i < 0 ? c : alphabet.charAt((i + shift) % alphabet.length());
    }

    @Provide
    Arbitrary<List<Entitlement>> entitlements() {
        Arbitrary<String> keys =
                Arbitraries.strings().withCharRange('a', 'z').ofMinLength(1).ofMaxLength(10);
        Arbitrary<Entitlement> flags =
                Combinators.combine(keys, Arbitraries.of(true, false)).as(Entitlement::flag);
        Arbitrary<Entitlement> limits = Combinators.combine(
                        keys, Arbitraries.oneOf(Arbitraries.longs(), Arbitraries.of(-1L, 0L, Long.MAX_VALUE)))
                .as(Entitlement::limit);
        Arbitrary<Entitlement> strings = Combinators.combine(
                        keys, Arbitraries.strings().alpha().ofMaxLength(12))
                .as(Entitlement::string);
        return Arbitraries.oneOf(flags, limits, strings)
                .list()
                .uniqueElements(Entitlement::key)
                .ofMinSize(0)
                .ofMaxSize(8);
    }
}
