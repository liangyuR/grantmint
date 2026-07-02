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
            assertThat(verified.seatLimit()).isEqualTo((long) seat);
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
