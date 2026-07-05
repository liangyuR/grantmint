package dev.hg.grantmint.core.token;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.core.codec.Base64Url;
import dev.hg.grantmint.core.codec.CanonicalJson;
import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.entitlement.Entitlement;
import dev.hg.grantmint.core.entitlement.EntitlementSet;
import dev.hg.grantmint.core.time.Clock;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class LicenseTokenTest {

    private static final SecureRandom RNG = new SecureRandom();
    private static final long IAT = 1_751_130_000L;
    private static final long EXP = 1_782_666_000L;

    private final KeyPair keyPair = Ed25519Keys.generate(RNG);
    private final LicenseTokenIssuer issuer = new LicenseTokenIssuer(new Ed25519Signer(keyPair.getPrivate(), "KP77"));

    @Test
    void issuedTokenHasThreePinnedHeaderSegments() {
        SignedToken token = issuer.issue(proLicense());
        TokenHeader header = TokenCodec.decodeHeader(token.headerSegment());

        assertThat(header.alg()).isEqualTo("EdDSA");
        assertThat(header.typ()).isEqualTo("GMT");
        assertThat(header.crv()).isEqualTo("Ed25519");
        assertThat(header.kid()).isEqualTo("KP77");
        assertThat(token.serialize().split("\\.")).hasSize(3);
    }

    @Test
    void fullRoundTripPreservesAllClaims() {
        TokenPayload original = proLicense();
        String token = issuer.sign(original);

        VerificationResult result =
                LicenseVerifier.verifyAt(token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));

        assertThat(result.isValid()).isTrue();
        TokenPayload decoded = result.payload();
        assertThat(decoded.lid()).isEqualTo(original.lid());
        assertThat(decoded.kid()).isEqualTo(original.kid());
        assertThat(decoded.prd()).isEqualTo(original.prd());
        assertThat(decoded.holder()).isEqualTo(original.holder());
        assertThat(decoded.exp()).isEqualTo(EXP);
        assertThat(decoded.seat()).isEqualTo(2);
        assertThat(decoded.constraints()).isEqualTo(original.constraints());
        assertThat(decoded.entitlements().isEnabled("team_sync")).isTrue();
        assertThat(decoded.entitlements().limit("max_devices", -99)).isEqualTo(2);
    }

    @Test
    void perpetualLicenseNeverExpires() {
        TokenPayload perpetual = new TokenPayload(
                1,
                "lic_x",
                "K1",
                "prd",
                "pol",
                new Holder("n", "e"),
                IAT,
                null,
                null,
                EntitlementSet.empty(),
                null,
                null);
        String token = issuer.sign(perpetual);

        VerificationResult farFuture = LicenseVerifier.verifyAt(
                token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(4_102_444_800L)));
        assertThat(farFuture.isValid()).isTrue();
    }

    @Test
    void algorithmConfusionIsRejectedBeforeSignatureCheck() {
        // Forge a header claiming alg=none, keep a real payload and a junk signature.
        Map<String, Object> noneHeader = new LinkedHashMap<>();
        noneHeader.put("alg", "none");
        noneHeader.put("typ", "GMT");
        noneHeader.put("kid", "KP77");
        noneHeader.put("crv", "Ed25519");
        String headerSeg = Base64Url.encode(CanonicalJson.serialize(noneHeader));
        String payloadSeg = TokenCodec.encodePayload(proLicense());
        String forged = headerSeg + "." + payloadSeg + ".AAAA";

        VerificationResult result =
                LicenseVerifier.verifyAt(forged, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.ALG_NOT_ALLOWED);
    }

    @Test
    void unknownSigningKeyIsForged() {
        String token = issuer.sign(proLicense());
        KeyPair other = Ed25519Keys.generate(RNG);
        VerificationResult result =
                LicenseVerifier.verifyAt(token, other.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.FORGED);
    }

    @Test
    void keyringSelectsKeyByHeaderKid() {
        String token = issuer.sign(proLicense());
        LicenseVerifier verifier = LicenseVerifier.ofKeyring(Map.of("KP77", keyPair.getPublic()));
        assertThat(verifier.verifyAt(token, Clock.fixed(Instant.ofEpochSecond(IAT)))
                        .isValid())
                .isTrue();

        LicenseVerifier wrongId = LicenseVerifier.ofKeyring(Map.of("OTHER", keyPair.getPublic()));
        assertThat(wrongId.verifyAt(token, Clock.fixed(Instant.ofEpochSecond(IAT)))
                        .reason())
                .isEqualTo(FailureReason.FORGED);
    }

    @Test
    void structurallyMalformedTokenIsMalformed() {
        VerificationResult result =
                LicenseVerifier.verifyAt("not-a-token", keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.MALFORMED);
    }

    @Test
    void curveConfusionIsRejectedBeforeSignatureCheck() {
        // A header with a contradictory curve, validly signed over its own bytes. The verifier must
        // pin crv=Ed25519 (not just alg) and reject it as ALG_NOT_ALLOWED before verifying the signature.
        Map<String, Object> header = TokenHeader.forSigningKey("KP77").toMap();
        header.put("crv", "P-256");
        String token = signRawClaims(header, proLicense().toClaimMap());

        VerificationResult result =
                LicenseVerifier.verifyAt(token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.ALG_NOT_ALLOWED);
    }

    @Test
    void foreignTokenTypeIsRejectedBeforeSignatureCheck() {
        // A validly-signed token whose typ is a generic 'JWT' rather than 'GMT'. The verifier must
        // refuse to treat a foreign token shape as a Grantmint license, before verifying the signature.
        Map<String, Object> header = TokenHeader.forSigningKey("KP77").toMap();
        header.put("typ", "JWT");
        String token = signRawClaims(header, proLicense().toClaimMap());

        VerificationResult result =
                LicenseVerifier.verifyAt(token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.WRONG_TYPE);
    }

    @Test
    void unknownFormatVersionIsRejected() {
        // A validly-signed token declaring a future format version (ver=2). A v1 verifier must
        // fail closed rather than interpret an unknown claim layout as v1.
        Map<String, Object> claims = proLicense().toClaimMap();
        claims.put("ver", 2);
        String token = signRawClaims(TokenHeader.forSigningKey("KP77").toMap(), claims);

        VerificationResult result =
                LicenseVerifier.verifyAt(token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.UNSUPPORTED_VERSION);
    }

    @Test
    void outOfRangeIntegerClaimIsMalformedNotThrown() {
        // A validly-signed token whose 'ver' overflows int. Verification must return MALFORMED, never
        // propagate an ArithmeticException — it is a boolean decision over untrusted input.
        Map<String, Object> claims = proLicense().toClaimMap();
        claims.put("ver", 9_999_999_999L);
        String token = signRawClaims(TokenHeader.forSigningKey("KP77").toMap(), claims);

        VerificationResult result =
                LicenseVerifier.verifyAt(token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result).isNotNull();
        assertThat(result.reason()).isEqualTo(FailureReason.MALFORMED);
    }

    @Test
    void oversizedEntitlementLimitIsMalformedNotThrown() {
        // A validly-signed token whose entitlement limit exceeds the 64-bit range. The integer-only
        // lexer rejects it at parse (CanonicalJson now refuses to even emit one), surfacing as
        // MALFORMED — never a leaked exception out of verification.
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"kid\":\"KP77\",\"crv\":\"Ed25519\"}";
        String payloadJson = "{\"ver\":1,\"lid\":\"l\",\"kid\":\"KP77\",\"prd\":\"p\",\"pol\":\"po\","
                + "\"hld\":{\"n\":\"n\",\"e\":\"e\"},\"iat\":" + IAT + ",\"exp\":" + EXP
                + ",\"ent\":{\"max_devices\":99999999999999999999}}";
        String token = signRawJson(headerJson, payloadJson);

        VerificationResult result =
                LicenseVerifier.verifyAt(token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.MALFORMED);
    }

    @Test
    void nonCanonicalSignatureEncodingIsMalformed() {
        // The signature segment is the one part of the token not covered by the signing input, so an
        // alternate base64url spelling of it decodes to the SAME 64 signature bytes (86 chars leave 4
        // unused trailing bits => 15 alternate spellings). Accepting one would let a single license
        // circulate as several distinct token strings — and split the verdict against the starter's
        // strict verifier. Every spelling but the canonical one must be MALFORMED.
        String token = issuer.sign(proLicense());
        String[] segments = token.split("\\.");
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        String sig = segments[2];
        int lastValue = alphabet.indexOf(sig.charAt(sig.length() - 1));
        assertThat(lastValue % 16)
                .as("canonical final character has zero trailing bits")
                .isZero();
        for (int bits = 1; bits <= 15; bits++) {
            String nonCanonical = sig.substring(0, sig.length() - 1) + alphabet.charAt(lastValue | bits);
            String remixed = segments[0] + "." + segments[1] + "." + nonCanonical;
            VerificationResult result =
                    LicenseVerifier.verifyAt(remixed, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
            assertThat(result.reason())
                    .as("non-canonical signature spelling %d must not verify", bits)
                    .isEqualTo(FailureReason.MALFORMED);
        }
    }

    @Test
    void fractionalTimestampClaimIsMalformed() {
        // CanonicalJson never emits a float, but a forged payload could carry one. A validly-signed
        // token with exp=1.5 must be MALFORMED, not silently truncated to a whole second.
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"kid\":\"KP77\",\"crv\":\"Ed25519\"}";
        String payloadJson = "{\"ver\":1,\"lid\":\"l\",\"kid\":\"KP77\",\"prd\":\"p\",\"pol\":\"po\","
                + "\"hld\":{\"n\":\"n\",\"e\":\"e\"},\"iat\":" + IAT + ",\"exp\":1.5,\"ent\":{}}";
        String token = signRawJson(headerJson, payloadJson);

        VerificationResult result =
                LicenseVerifier.verifyAt(token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.MALFORMED);
    }

    @Test
    void matchingExpectedProductVerifies() {
        String token = issuer.sign(proLicense());
        VerificationResult result = LicenseVerifier.verifyAt(
                token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)), "prod_acme_notes");
        assertThat(result.isValid()).isTrue();
        assertThat(result.payload().prd()).isEqualTo("prod_acme_notes");
    }

    @Test
    void mismatchedExpectedProductIsWrongProduct() {
        // Same key pair signs a token for product A; presenting it to product B's gate must be rejected
        // as WRONG_PRODUCT even though the signature is authentic — the cross-product acceptance guard.
        String token = issuer.sign(proLicense());
        VerificationResult result = LicenseVerifier.verifyAt(
                token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)), "prod_other_app");
        assertThat(result.reason()).isEqualTo(FailureReason.WRONG_PRODUCT);
    }

    @Test
    void nullExpectedProductSkipsTheProductCheck() {
        // Backward-compatible: the no-product overload accepts any authentic token regardless of prd.
        String token = issuer.sign(proLicense());
        VerificationResult result =
                LicenseVerifier.verifyAt(token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.isValid()).isTrue();
    }

    @Test
    void wrongProductIsRejectedBeforeExpiry() {
        // Precedence: an authentic-but-expired token for the wrong product reports WRONG_PRODUCT, not
        // EXPIRED — the product gate runs before the temporal window.
        String token = issuer.sign(proLicense());
        VerificationResult result = LicenseVerifier.verifyAt(
                token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(EXP + 1)), "prod_other_app");
        assertThat(result.reason()).isEqualTo(FailureReason.WRONG_PRODUCT);
    }

    @Test
    void tokenOmittingExpIsMalformed() {
        // exp is required (its value may be null for perpetual). A validly-signed token that drops the
        // exp key entirely must be MALFORMED — never silently admitted as a perpetual license.
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"kid\":\"KP77\",\"crv\":\"Ed25519\"}";
        String payloadJson = "{\"ver\":1,\"lid\":\"l\",\"kid\":\"KP77\",\"prd\":\"p\",\"pol\":\"po\","
                + "\"hld\":{\"n\":\"n\",\"e\":\"e\"},\"iat\":" + IAT + ",\"ent\":{}}";
        String token = signRawJson(headerJson, payloadJson);

        VerificationResult result =
                LicenseVerifier.verifyAt(token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.MALFORMED);
    }

    @Test
    void tokenWithExplicitNullExpIsPerpetualNotMalformed() {
        // The counterpart to the above: exp present with a null value is a valid perpetual license.
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"kid\":\"KP77\",\"crv\":\"Ed25519\"}";
        String payloadJson = "{\"ver\":1,\"lid\":\"l\",\"kid\":\"KP77\",\"prd\":\"p\",\"pol\":\"po\","
                + "\"hld\":{\"n\":\"n\",\"e\":\"e\"},\"iat\":" + IAT + ",\"exp\":null,\"ent\":{}}";
        String token = signRawJson(headerJson, payloadJson);

        VerificationResult result = LicenseVerifier.verifyAt(
                token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(4_102_444_800L)));
        assertThat(result.isValid()).isTrue();
        assertThat(result.payload().exp()).isNull();
    }

    @Test
    void emptyRequiredStringClaimIsMalformed() {
        // The claim table requires the identifying string claims to be non-empty. A validly-signed
        // token with prd="" must be MALFORMED — every verifier implementation rejects it, so the
        // reference must never accept it (cross-verifier parity).
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"kid\":\"KP77\",\"crv\":\"Ed25519\"}";
        String payloadJson = "{\"ver\":1,\"lid\":\"l\",\"kid\":\"KP77\",\"prd\":\"\",\"pol\":\"po\","
                + "\"hld\":{\"n\":\"n\",\"e\":\"e\"},\"iat\":" + IAT + ",\"exp\":" + EXP + ",\"ent\":{}}";
        String token = signRawJson(headerJson, payloadJson);

        VerificationResult result =
                LicenseVerifier.verifyAt(token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.MALFORMED);
    }

    @Test
    void emptyHolderFieldIsMalformed() {
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"kid\":\"KP77\",\"crv\":\"Ed25519\"}";
        String payloadJson = "{\"ver\":1,\"lid\":\"l\",\"kid\":\"KP77\",\"prd\":\"p\",\"pol\":\"po\","
                + "\"hld\":{\"n\":\"n\",\"e\":\"\"},\"iat\":" + IAT + ",\"exp\":" + EXP + ",\"ent\":{}}";
        String token = signRawJson(headerJson, payloadJson);

        VerificationResult result =
                LicenseVerifier.verifyAt(token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.MALFORMED);
    }

    @Test
    void missingOrWrongTypedEntClaimIsMalformed() {
        // ent is required and must be an object — a token without it (or with ent=42) was silently
        // read as an empty entitlement set before the full-surface audit; now it is MALFORMED, in
        // agreement with the starter/Swift/Go verifiers.
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"kid\":\"KP77\",\"crv\":\"Ed25519\"}";
        String withoutEnt = "{\"ver\":1,\"lid\":\"l\",\"kid\":\"KP77\",\"prd\":\"p\",\"pol\":\"po\","
                + "\"hld\":{\"n\":\"n\",\"e\":\"e\"},\"iat\":" + IAT + ",\"exp\":" + EXP + "}";
        String numericEnt = "{\"ver\":1,\"lid\":\"l\",\"kid\":\"KP77\",\"prd\":\"p\",\"pol\":\"po\","
                + "\"hld\":{\"n\":\"n\",\"e\":\"e\"},\"iat\":" + IAT + ",\"exp\":" + EXP + ",\"ent\":42}";

        for (String payloadJson : new String[] {withoutEnt, numericEnt}) {
            VerificationResult result = LicenseVerifier.verifyAt(
                    signRawJson(headerJson, payloadJson), keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
            assertThat(result.reason()).isEqualTo(FailureReason.MALFORMED);
        }
    }

    @Test
    void wrongTypedConClaimIsMalformed() {
        // con is optional, but when present it must be an object — never silently dropped.
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"kid\":\"KP77\",\"crv\":\"Ed25519\"}";
        String payloadJson = "{\"ver\":1,\"lid\":\"l\",\"kid\":\"KP77\",\"prd\":\"p\",\"pol\":\"po\","
                + "\"hld\":{\"n\":\"n\",\"e\":\"e\"},\"iat\":" + IAT + ",\"exp\":" + EXP + ",\"ent\":{},\"con\":7}";
        String token = signRawJson(headerJson, payloadJson);

        VerificationResult result =
                LicenseVerifier.verifyAt(token, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.MALFORMED);
    }

    @Test
    void paddedSegmentIsMalformed() {
        // Padding is outside the wire contract; a '='-padded segment must be rejected, not tolerated.
        String[] segments = issuer.sign(proLicense()).split("\\.");
        String paddedHeader = segments[0] + "=." + segments[1] + "." + segments[2];

        VerificationResult result =
                LicenseVerifier.verifyAt(paddedHeader, keyPair.getPublic(), Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.MALFORMED);
    }

    /** Sign an arbitrary header+payload claim map (canonical JSON) under the test key — for forging edge cases. */
    private String signRawClaims(Map<String, Object> header, Map<String, Object> payload) {
        String headerSegment = Base64Url.encode(CanonicalJson.serialize(header));
        String payloadSegment = Base64Url.encode(CanonicalJson.serialize(payload));
        return assembleSigned(headerSegment, payloadSegment);
    }

    /** Sign arbitrary raw JSON bytes (for shapes CanonicalJson refuses to emit, e.g. a float claim). */
    private String signRawJson(String headerJson, String payloadJson) {
        String headerSegment = Base64Url.encode(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadSegment = Base64Url.encode(payloadJson.getBytes(StandardCharsets.UTF_8));
        return assembleSigned(headerSegment, payloadSegment);
    }

    private String assembleSigned(String headerSegment, String payloadSegment) {
        byte[] signature = new Ed25519Signer(keyPair.getPrivate(), "KP77")
                .sign((headerSegment + "." + payloadSegment).getBytes(StandardCharsets.US_ASCII));
        return headerSegment + "." + payloadSegment + "." + Base64Url.encode(signature);
    }

    private TokenPayload proLicense() {
        Map<String, Object> constraints = new LinkedHashMap<>();
        constraints.put("seats", 2L);
        constraints.put("nodeLocked", true);
        EntitlementSet entitlements = EntitlementSet.of(
                Entitlement.flag("team_sync", true),
                Entitlement.flag("ai_assist", true),
                Entitlement.limit("max_devices", 2),
                Entitlement.limit("max_projects", 10));
        return new TokenPayload(
                1,
                "lic_01JZ8X9Q4R7M2K3P5T6V8W0Y2A",
                "K7P2-9QXM-4T1A",
                "prod_acme_notes",
                "pol_pro_annual",
                new Holder("Jane Doe", "jane@example.com"),
                IAT,
                null,
                EXP,
                entitlements,
                constraints,
                2);
    }
}
