package dev.hg.grantmint.client.verify;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * The starter's half of the offline-trust guarantee: it must verify the pinned cross-verifier
 * vector byte-for-byte identically to the reference implementation and the Swift/Go verifiers.
 * Every value here is copied verbatim from docs/testing/CROSS_VERIFIER_FIXTURES.md — if that vector
 * rotates, update this test alongside it.
 */
class CrossVerifierFixtureTest {

    private static final String PUBLIC_KEY_HEX = "34687417cc2f326d57e0a3702bb8bafda49bf8bdbb9f9ed224d0e0deb8be4101";
    // The published test vector from CROSS_VERIFIER_FIXTURES.md — not a credential.
    private static final String TOKEN =
            "eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJHTUsxIiwidHlwIjoiR01UIn0." // gitleaks:allow
                    + "eyJjb24iOnsibm9kZUxvY2tlZCI6dHJ1ZSwic2VhdHMiOjJ9LCJlbnQiOnsiYWlfYXNzaXN0Ijp0cnVlLCJtYXhfZGV2aWNlcyI6"
                    + "MiwibWF4X3Byb2plY3RzIjoxMCwidGVhbV9zeW5jIjp0cnVlLCJ0aWVyIjoicHJvIn0sImV4cCI6MTc4MjY2NjAwMCwiaGxkIjp7"
                    + "ImUiOiJqYW5lQGV4YW1wbGUuY29tIiwibiI6IkphbmUgRG9lIn0sImlhdCI6MTc1MTEzMDAwMCwia2lkIjoiSzdQMi05UVhNLTRU"
                    + "MUEiLCJsaWQiOiJsaWNfMDFKWjhYOVE0UjdNMkszUDVUNlY4VzBZMkEiLCJwb2wiOiJwb2xfcHJvX2FubnVhbCIsInByZCI6InBy"
                    + "b2RfYWNtZV9ub3RlcyIsInNlYXQiOjIsInZlciI6MX0."
                    + "dE2gDMZMeggftOMOeLjAK3fOu5Ax8b9DKSYSGb0N7pWoUZbZ43jdMRzrNTuQ734MsBGmFEi5bDoCFpJ0js8zDg";
    private static final long IAT = 1751130000L;
    private static final long EXP = 1782666000L;

    private final OfflineTokenVerifier verifier = new OfflineTokenVerifier(
            Base64.getEncoder().encodeToString(HexFormat.of().parseHex(PUBLIC_KEY_HEX)));

    @Test
    void thePinnedVectorVerifiesAtIssueTimeWithItsExactClaims() {
        VerifiedToken verified = verifier.verifyAt(TOKEN, Instant.ofEpochSecond(IAT));

        assertThat(verified.keyId()).isEqualTo("K7P2-9QXM-4T1A");
        assertThat(verified.licenseId()).isEqualTo("lic_01JZ8X9Q4R7M2K3P5T6V8W0Y2A");
        assertThat(verified.product()).isEqualTo("prod_acme_notes");
        assertThat(verified.policy()).isEqualTo("pol_pro_annual");
        assertThat(verified.holderName()).isEqualTo("Jane Doe");
        assertThat(verified.holderEmail()).isEqualTo("jane@example.com");
        assertThat(verified.issuedAt()).isEqualTo(Instant.ofEpochSecond(IAT));
        assertThat(verified.expiresAt()).isEqualTo(Instant.ofEpochSecond(EXP));
        assertThat(verified.seatLimit()).isEqualTo(2L);
        assertThat(verified.entitlements())
                .containsEntry("ai_assist", true)
                .containsEntry("max_devices", 2L)
                .containsEntry("max_projects", 10L)
                .containsEntry("team_sync", true)
                .containsEntry("tier", "pro");
        assertThat(verified.constraints()).containsEntry("nodeLocked", true).containsEntry("seats", 2L);
    }

    @Test
    void theVectorIsExpiredAtExactlyExpBecauseExpIsExclusive() {
        assertThatThrownBy(() -> verifier.verifyAt(TOKEN, Instant.ofEpochSecond(EXP)))
                .isInstanceOf(TokenVerificationException.class)
                .satisfies(e -> assertThat(((TokenVerificationException) e).reason())
                        .isEqualTo(TokenVerificationException.Reason.EXPIRED));
        // …but still verifies one second earlier.
        assertThat(verifier.verifyAt(TOKEN, Instant.ofEpochSecond(EXP - 1))).isNotNull();
    }

    @Test
    void paddedSegmentsAndWrongSegmentCountsAreMalformed() {
        assertThatThrownBy(() -> verifier.verifyAt(TOKEN + "=", Instant.ofEpochSecond(IAT)))
                .isInstanceOf(TokenVerificationException.class)
                .satisfies(e -> assertThat(((TokenVerificationException) e).reason())
                        .isEqualTo(TokenVerificationException.Reason.MALFORMED));
        assertThatThrownBy(() -> verifier.verifyAt(TOKEN + ".extra", Instant.ofEpochSecond(IAT)))
                .isInstanceOf(TokenVerificationException.class);
        assertThatThrownBy(() -> verifier.verifyAt("a.b", Instant.ofEpochSecond(IAT)))
                .isInstanceOf(TokenVerificationException.class);
    }

    @Test
    void paddedPayloadSegmentOfThePinnedVectorIsMalformedNotInvalidSignature() {
        // The reason-parity vector (GRANTMINT-166): '='-pad the authentic token's payload segment and
        // every verifier must say MALFORMED — structure is gate zero, checked before any signature
        // work, so the reason cannot drift to INVALID_SIGNATURE/FORGED in any implementation.
        String[] parts = TOKEN.split("\\.");
        String paddedPayload = parts[0] + "." + parts[1] + "=." + parts[2];

        assertThatThrownBy(() -> verifier.verifyAt(paddedPayload, Instant.ofEpochSecond(IAT)))
                .isInstanceOf(TokenVerificationException.class)
                .satisfies(e -> assertThat(((TokenVerificationException) e).reason())
                        .isEqualTo(TokenVerificationException.Reason.MALFORMED));
    }

    @Test
    void aTamperedPayloadCharacterFailsTheSignature() {
        int payloadMiddle = TOKEN.indexOf('.') + 10;
        char original = TOKEN.charAt(payloadMiddle);
        char flipped = original == 'A' ? 'B' : 'A';
        String tampered = TOKEN.substring(0, payloadMiddle) + flipped + TOKEN.substring(payloadMiddle + 1);

        assertThatThrownBy(() -> verifier.verifyAt(tampered, Instant.ofEpochSecond(IAT)))
                .isInstanceOf(TokenVerificationException.class);
    }

    @Test
    void aHeaderWithoutThePinnedAlgorithmIsRejectedBeforeSignatureWork() {
        // Same payload+signature, header swapped for alg=none — the classic JWT confusion attack.
        String noneHeader = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"crv\":\"Ed25519\",\"kid\":\"GMK1\",\"typ\":\"GMT\"}"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String[] parts = TOKEN.split("\\.");
        String confused = noneHeader + "." + parts[1] + "." + parts[2];

        assertThatThrownBy(() -> verifier.verifyAt(confused, Instant.ofEpochSecond(IAT)))
                .isInstanceOf(TokenVerificationException.class)
                .satisfies(e -> assertThat(((TokenVerificationException) e).reason())
                        .isEqualTo(TokenVerificationException.Reason.ALG_NOT_ALLOWED));
    }

    @Test
    void duplicateObjectKeysAreMalformedNeverFirstOrLastWins() {
        String dupHeader = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(
                        "{\"alg\":\"EdDSA\",\"alg\":\"EdDSA\",\"crv\":\"Ed25519\",\"kid\":\"GMK1\",\"typ\":\"GMT\"}"
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String[] parts = TOKEN.split("\\.");
        String duplicated = dupHeader + "." + parts[1] + "." + parts[2];

        assertThatThrownBy(() -> verifier.verifyAt(duplicated, Instant.ofEpochSecond(IAT)))
                .isInstanceOf(TokenVerificationException.class)
                .satisfies(e -> assertThat(((TokenVerificationException) e).reason())
                        .isEqualTo(TokenVerificationException.Reason.MALFORMED));
    }
}
