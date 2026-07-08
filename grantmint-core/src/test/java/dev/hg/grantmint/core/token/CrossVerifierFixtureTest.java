package dev.hg.grantmint.core.token;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.entitlement.Entitlement;
import dev.hg.grantmint.core.entitlement.EntitlementSet;
import dev.hg.grantmint.core.time.Clock;
import java.security.PublicKey;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The cross-language parity vector — the offline-trust guarantee made executable.
 *
 * <p>Ed25519 (RFC 8032) signs <em>deterministically</em>: a fixed seed plus a fixed message always
 * yields the same signature. Combined with Grantmint's canonical JSON (code-point-sorted keys, no
 * whitespace, integers only) and unpadded base64url, that makes the entire serialized token
 * byte-for-byte reproducible. This test pins that exact token.
 *
 * <p>The same fixture (seed, public key, token, decoded claims) is published in
 * docs/testing/CROSS_VERIFIER_FIXTURES.md so the Java starter, the Swift (CryptoKit) verifier, and
 * the Go ({@code crypto/ed25519}) verifier can all be checked against one authoritative vector. If a
 * change to the codec, header, or claim ordering ever shifts a byte, {@link #tokenIsByteForByteStable}
 * fails here first — a signal to regenerate the published fixture and re-verify every language.
 */
class CrossVerifierFixtureTest {

    // ── The authoritative fixture (keep in lockstep with docs/testing/CROSS_VERIFIER_FIXTURES.md). ──
    static final String SEED_HEX = "52ec811207633ad9f4a283d8eb887630e6183f7b6dfa8ea02fc4b9f9c7438aec";
    static final String PUBLIC_KEY_HEX = "34687417cc2f326d57e0a3702bb8bafda49bf8bdbb9f9ed224d0e0deb8be4101";
    static final String EXPECTED_TOKEN = "eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJHTUsxIiwidHlwIjoiR01UIn0"
            + ".eyJjb24iOnsibm9kZUxvY2tlZCI6dHJ1ZSwic2VhdHMiOjJ9LCJlbnQiOnsiYWlfYXNzaXN0Ijp0cnVlLCJtYXhf"
            + "ZGV2aWNlcyI6MiwibWF4X3Byb2plY3RzIjoxMCwidGVhbV9zeW5jIjp0cnVlLCJ0aWVyIjoicHJvIn0sImV4cCI6MTc4"
            + "MjY2NjAwMCwiaGxkIjp7ImUiOiJqYW5lQGV4YW1wbGUuY29tIiwibiI6IkphbmUgRG9lIn0sImlhdCI6MTc1MTEzMDAw"
            + "MCwia2lkIjoiSzdQMi05UVhNLTRUMUEiLCJsaWQiOiJsaWNfMDFKWjhYOVE0UjdNMkszUDVUNlY4VzBZMkEiLCJwb2wi"
            + "OiJwb2xfcHJvX2FubnVhbCIsInByZCI6InByb2RfYWNtZV9ub3RlcyIsInNlYXQiOjIsInZlciI6MX0"
            + ".dE2gDMZMeggftOMOeLjAK3fOu5Ax8b9DKSYSGb0N7pWoUZbZ43jdMRzrNTuQ734MsBGmFEi5bDoCFpJ0js8zDg";

    static final long IAT = 1_751_130_000L;
    static final long EXP = 1_782_666_000L;
    static final String SIGNING_KEY_ID = "GMK1";

    @Test
    void tokenIsByteForByteStable() {
        Ed25519Signer signer = Ed25519Signer.fromRawSeed(HexFormat.of().parseHex(SEED_HEX), SIGNING_KEY_ID);
        String token = new LicenseTokenIssuer(signer).sign(fixturePayload());

        // Deterministic signing + canonical encoding ⇒ exactly the published bytes. A mismatch here
        // means the wire format drifted and every published verifier must be re-checked.
        assertThat(token).isEqualTo(EXPECTED_TOKEN);
    }

    @Test
    void seedAndPublicKeyAreAMatchedPair() {
        // The published seed signs a token that the published public key verifies — proving the two
        // halves of the fixture belong together for any language reconstructing them from the hex.
        PublicKey publicKey = Ed25519Keys.decodePublicKey(HexFormat.of().parseHex(PUBLIC_KEY_HEX));
        VerificationResult result =
                LicenseVerifier.verifyAt(EXPECTED_TOKEN, publicKey, Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.isValid()).isTrue();
    }

    @Test
    void publishedTokenVerifiesAndCarriesEveryClaim() {
        PublicKey publicKey = Ed25519Keys.decodePublicKey(HexFormat.of().parseHex(PUBLIC_KEY_HEX));
        VerificationResult result =
                LicenseVerifier.verifyAt(EXPECTED_TOKEN, publicKey, Clock.fixed(Instant.ofEpochSecond(IAT)));

        assertThat(result.isValid()).isTrue();
        TokenPayload p = result.payload();
        assertThat(p.ver()).isEqualTo(1);
        assertThat(p.lid()).isEqualTo("lic_01JZ8X9Q4R7M2K3P5T6V8W0Y2A");
        assertThat(p.kid()).isEqualTo("K7P2-9QXM-4T1A");
        assertThat(p.prd()).isEqualTo("prod_acme_notes");
        assertThat(p.pol()).isEqualTo("pol_pro_annual");
        assertThat(p.holder()).isEqualTo(new Holder("Jane Doe", "jane@example.com"));
        assertThat(p.iat()).isEqualTo(IAT);
        assertThat(p.exp()).isEqualTo(EXP);
        assertThat(p.seat()).isEqualTo(2);
        assertThat(p.entitlements().isEnabled("team_sync")).isTrue();
        assertThat(p.entitlements().isEnabled("ai_assist")).isTrue();
        assertThat(p.entitlements().limit("max_devices", -1)).isEqualTo(2);
        assertThat(p.entitlements().limit("max_projects", -1)).isEqualTo(10);
        assertThat(p.entitlements().string("tier", null)).isEqualTo("pro");
    }

    @Test
    void paddedPayloadSegmentOfPublishedTokenIsMalformedNotForged() {
        // The reason-parity vector (GRANTMINT-166): '='-pad the authentic token's payload segment and
        // every verifier must say MALFORMED. Structure is gate zero — the corrupt segment is rejected
        // before any signature work, so the reason can never drift to FORGED/INVALID_SIGNATURE in an
        // implementation that happens to check the (doomed) signature first.
        PublicKey publicKey = Ed25519Keys.decodePublicKey(HexFormat.of().parseHex(PUBLIC_KEY_HEX));
        String[] segments = EXPECTED_TOKEN.split("\\.");
        String paddedPayload = segments[0] + "." + segments[1] + "=." + segments[2];

        VerificationResult result =
                LicenseVerifier.verifyAt(paddedPayload, publicKey, Clock.fixed(Instant.ofEpochSecond(IAT)));
        assertThat(result.reason()).isEqualTo(FailureReason.MALFORMED);
    }

    @Test
    void publishedTokenIsExpiredPastExp() {
        // Every language verifier must agree that exp is exclusive: rejected at exactly exp and after.
        PublicKey publicKey = Ed25519Keys.decodePublicKey(HexFormat.of().parseHex(PUBLIC_KEY_HEX));
        VerificationResult result =
                LicenseVerifier.verifyAt(EXPECTED_TOKEN, publicKey, Clock.fixed(Instant.ofEpochSecond(EXP)));
        assertThat(result.reason()).isEqualTo(FailureReason.EXPIRED);
    }

    /** The exact claim set encoded in {@link #EXPECTED_TOKEN}; mirrors the published fixture. */
    static TokenPayload fixturePayload() {
        Map<String, Object> constraints = new LinkedHashMap<>();
        constraints.put("seats", 2L);
        constraints.put("nodeLocked", true);
        EntitlementSet ent = EntitlementSet.of(
                Entitlement.flag("team_sync", true),
                Entitlement.flag("ai_assist", true),
                Entitlement.limit("max_devices", 2),
                Entitlement.limit("max_projects", 10),
                Entitlement.string("tier", "pro"));
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
                ent,
                constraints,
                2);
    }
}
