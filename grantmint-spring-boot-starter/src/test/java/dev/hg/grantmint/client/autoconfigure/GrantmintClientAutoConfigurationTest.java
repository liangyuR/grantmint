package dev.hg.grantmint.client.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.client.EntitlementChecker;
import dev.hg.grantmint.client.LicenseValidator;
import dev.hg.grantmint.client.verify.OfflineTokenVerifier;
import dev.hg.grantmint.core.crypto.Ed25519Keys;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * The one-dependency-plus-properties contract: with a public key configured, the starter exposes
 * {@link LicenseValidator} and {@link EntitlementChecker}; the mode picks the validator flavour;
 * disabling the client (or omitting it from the classpath) yields nothing; and any bean can be
 * overridden by the consuming app. See docs/features/CLIENT_SDK.md.
 */
class GrantmintClientAutoConfigurationTest {

    private static final String PUBLIC_KEY = freshPublicKey();

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(GrantmintClientAutoConfiguration.class));

    @Test
    void hybridIsTheDefaultModeAndExposesAllBeans() {
        runner.withPropertyValues(
                        "grantmint.client.public-key=" + PUBLIC_KEY,
                        "grantmint.client.server-url=https://licenses.example.com")
                .run(context -> {
                    assertThat(context).hasSingleBean(OfflineTokenVerifier.class);
                    assertThat(context).hasSingleBean(LicenseValidator.class);
                    assertThat(context).hasSingleBean(EntitlementChecker.class);
                });
    }

    @Test
    void offlineModeNeedsNoServerUrl() {
        runner.withPropertyValues("grantmint.client.public-key=" + PUBLIC_KEY, "grantmint.client.mode=offline")
                .run(context -> {
                    assertThat(context).hasSingleBean(LicenseValidator.class);
                    assertThat(context).hasSingleBean(EntitlementChecker.class);
                });
    }

    @Test
    void disablingTheClientWiresNothing() {
        runner.withPropertyValues("grantmint.client.enabled=false", "grantmint.client.public-key=" + PUBLIC_KEY)
                .run(context -> {
                    assertThat(context).doesNotHaveBean(LicenseValidator.class);
                    assertThat(context).doesNotHaveBean(EntitlementChecker.class);
                });
    }

    @Test
    void aMissingPublicKeyFailsFastWithAPointedMessage() {
        runner.withPropertyValues("grantmint.client.mode=offline").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasRootCauseMessage(
                            "grantmint.client.public-key is required — base64 of the 32-byte raw Ed25519 public key");
        });
    }

    @Test
    void aUserDeclaredValidatorBeanWinsOverTheAutoConfiguredOne() {
        runner.withPropertyValues("grantmint.client.public-key=" + PUBLIC_KEY, "grantmint.client.mode=offline")
                .withBean(
                        "myValidator",
                        LicenseValidator.class,
                        () -> LicenseValidator.offlineOnly(
                                new OfflineTokenVerifier(PUBLIC_KEY),
                                new dev.hg.grantmint.client.GrantmintClientProperties()))
                .run(context -> {
                    assertThat(context).hasSingleBean(LicenseValidator.class);
                    assertThat(context).hasBean("myValidator");
                });
    }

    private static String freshPublicKey() {
        KeyPair pair = Ed25519Keys.generate(new SecureRandom());
        return Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(pair.getPublic()));
    }
}
