package dev.hg.grantmint.core.token;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.core.codec.CanonicalJson;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import java.util.HexFormat;
import java.util.Map;
import org.junit.jupiter.api.Test;

class OfflineDeviceFixtureTest {
    @Test
    @SuppressWarnings("unchecked")
    void javaIssuanceMatchesTheSharedRustCertificateAndTimeReceipt() throws Exception {
        try (var input = getClass().getResourceAsStream("/offline-device-v2.json")) {
            Map<String, Object> fixture = (Map<String, Object>) CanonicalJson.parse(input.readAllBytes());
            var signer = Ed25519Signer.fromRawSeed(
                    HexFormat.of().parseHex((String) fixture.get("serverSeedHex")), "fixture-signing-key");
            assertThat(OfflineDeviceTokens.sign(signer, "GMT", (Map<String, Object>) fixture.get("claims")))
                    .isEqualTo(fixture.get("token"));
            assertThat(OfflineDeviceTokens.sign(signer, "GMT-TIME", (Map<String, Object>) fixture.get("receiptClaims")))
                    .isEqualTo(fixture.get("timeReceipt"));
        }
    }
}
