package dev.hg.grantmint.client;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.client.verify.OfflineTokenVerifier;
import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * The public {@link LicenseStatus.Reason} mapping keeps the distinctions an app can act on
 * (2026-07-05 audit, GRANTMINT-149): an unknown-format-version token is authentic — the right user
 * action is "update this app" — so it must NOT collapse into INVALID_SIGNATURE the way the
 * structural defects deliberately do.
 */
class LicenseValidatorReasonMappingTest {

    private static final Instant NOW = Instant.parse("2026-06-28T12:00:00Z");

    @Test
    void unknownFormatVersionSurfacesDistinctlyNotAsInvalidSignature() {
        KeyPair keys = Ed25519Keys.generate(new SecureRandom());
        Ed25519Signer signer = new Ed25519Signer(keys.getPrivate(), "GMK1");
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"GMT\",\"kid\":\"GMK1\",\"crv\":\"Ed25519\"}";
        String payloadJson = "{\"ver\":2,\"lid\":\"l\",\"kid\":\"K7P2-9QXM-4T1A\",\"prd\":\"acme-notes\","
                + "\"pol\":\"po\",\"hld\":{\"n\":\"n\",\"e\":\"e\"},\"iat\":" + NOW.getEpochSecond()
                + ",\"exp\":null,\"ent\":{}}";
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String headerSeg = b64.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadSeg = b64.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        byte[] sig = signer.sign((headerSeg + "." + payloadSeg).getBytes(StandardCharsets.US_ASCII));
        String token = headerSeg + "." + payloadSeg + "." + b64.encodeToString(sig);

        OfflineTokenVerifier verifier = new OfflineTokenVerifier(
                Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(keys.getPublic())),
                Clock.fixed(NOW, ZoneOffset.UTC));
        LicenseStatus status = LicenseValidator.offlineOnly(verifier, new GrantmintClientProperties())
                .verifyOffline(token);

        assertThat(status.valid()).isFalse();
        assertThat(status.reason()).isEqualTo(LicenseStatus.Reason.UNSUPPORTED_VERSION);
        // The credential is authentic (the signature spoke before the version gate), so its key id
        // is trusted and surfaced.
        assertThat(status.keyId()).isEqualTo("K7P2-9QXM-4T1A");

        // The structural collapse stays deliberate: a forged token is INVALID_SIGNATURE, keyId-less.
        String forged = headerSeg + "." + payloadSeg + "." + b64.encodeToString(new byte[64]);
        LicenseStatus forgedStatus = LicenseValidator.offlineOnly(verifier, new GrantmintClientProperties())
                .verifyOffline(forged);
        assertThat(forgedStatus.reason()).isEqualTo(LicenseStatus.Reason.INVALID_SIGNATURE);
        assertThat(forgedStatus.keyId()).isNull();
    }
}
