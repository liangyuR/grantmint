package dev.hg.grantmint.core.token;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.core.codec.Base64Url;
import dev.hg.grantmint.core.codec.CanonicalJson;
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
