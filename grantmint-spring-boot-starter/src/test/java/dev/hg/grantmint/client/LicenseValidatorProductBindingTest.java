package dev.hg.grantmint.client;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.client.verify.OfflineTokenVerifier;
import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.entitlement.EntitlementSet;
import dev.hg.grantmint.core.token.Holder;
import dev.hg.grantmint.core.token.LicenseTokenIssuer;
import dev.hg.grantmint.core.token.TokenPayload;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * Product binding surfaces as {@link LicenseStatus.Reason#WRONG_PRODUCT}, not INVALID_SIGNATURE —
 * the credential is authentic, it just belongs to a different product, and callers may want to say
 * so. The M13 audit found the reason collapsed into INVALID_SIGNATURE with WRONG_PRODUCT dead code.
 */
class LicenseValidatorProductBindingTest {

    private static final Instant NOW = Instant.parse("2026-06-28T12:00:00Z");

    @Test
    void tokenForAnotherProductReportsWrongProductNotInvalidSignature() {
        KeyPair keys = Ed25519Keys.generate(new SecureRandom());
        String token = new LicenseTokenIssuer(new Ed25519Signer(keys.getPrivate(), "GMK1"))
                .sign(new TokenPayload(
                        TokenPayload.CURRENT_VERSION,
                        "lic_binding",
                        "K7P2-9QXM-4T1A",
                        "acme-notes",
                        "pro-annual",
                        new Holder("Jane Doe", "jane@example.com"),
                        NOW.getEpochSecond(),
                        null,
                        null,
                        EntitlementSet.empty(),
                        null,
                        2));

        GrantmintClientProperties props = new GrantmintClientProperties();
        props.setProduct("some-other-app");
        OfflineTokenVerifier verifier = new OfflineTokenVerifier(
                Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(keys.getPublic())),
                Clock.fixed(NOW, ZoneOffset.UTC));
        LicenseValidator validator = LicenseValidator.offlineOnly(verifier, props);

        LicenseStatus status = validator.verifyOffline(token);
        assertThat(status.valid()).isFalse();
        assertThat(status.reason()).isEqualTo(LicenseStatus.Reason.WRONG_PRODUCT);
        assertThat(status.keyId()).isEqualTo("K7P2-9QXM-4T1A");

        // And the binding is not overreach: the same token for the right product verifies.
        props.setProduct("acme-notes");
        assertThat(LicenseValidator.offlineOnly(verifier, props)
                        .verifyOffline(token)
                        .valid())
                .isTrue();
    }
}
