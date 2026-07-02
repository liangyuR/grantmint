package dev.hg.grantmint.client.autoconfigure;

import dev.hg.grantmint.client.EntitlementChecker;
import dev.hg.grantmint.client.GrantmintClientProperties;
import dev.hg.grantmint.client.LicenseValidator;
import dev.hg.grantmint.client.verify.OfflineTokenVerifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configures the Grantmint client: one dependency plus {@code grantmint.client.*} properties
 * yields {@link LicenseValidator} and {@link EntitlementChecker} beans. Every bean is
 * {@code @ConditionalOnMissingBean}, so any of them can be replaced by declaring your own (a fake
 * always-Pro validator in tests, a custom online transport, …). See docs/features/CLIENT_SDK.md.
 */
@AutoConfiguration
@ConditionalOnClass(LicenseValidator.class)
@ConditionalOnProperty(prefix = "grantmint.client", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(GrantmintClientProperties.class)
public class GrantmintClientAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public OfflineTokenVerifier offlineTokenVerifier(GrantmintClientProperties props) {
        if (props.getPublicKey() == null || props.getPublicKey().isBlank()) {
            throw new IllegalStateException(
                    "grantmint.client.public-key is required — base64 of the 32-byte raw Ed25519 public key");
        }
        // Decodes the base64 public key once; the verify key is reused for every check.
        return new OfflineTokenVerifier(props.getPublicKey());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "grantmint.client", name = "mode", havingValue = "offline")
    public LicenseValidator offlineOnlyValidator(OfflineTokenVerifier verifier, GrantmintClientProperties props) {
        return LicenseValidator.offlineOnly(verifier, props);
    }

    @Bean
    @ConditionalOnMissingBean
    public LicenseValidator hybridValidator(OfflineTokenVerifier verifier, GrantmintClientProperties props) {
        // Online layer adds activation/seat/revocation truth; offline is the fast baseline.
        // Covers mode=hybrid (default) and mode=online; mode=offline is claimed by the bean above.
        return LicenseValidator.hybrid(verifier, props);
    }

    @Bean
    @ConditionalOnMissingBean
    public EntitlementChecker entitlementChecker(LicenseValidator validator) {
        return new EntitlementChecker(validator);
    }
}
