package dev.hg.grantmint.server.validation;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the validation-path infrastructure: binds {@link ValidationProperties} and builds the
 * shared {@link ValidationCache} from them. The cache is a singleton so every request and every
 * eviction hook see the same store.
 */
@Configuration
@EnableConfigurationProperties(ValidationProperties.class)
public class ValidationConfig {

    @Bean
    ValidationCache validationCache(ValidationProperties properties) {
        return new ValidationCache(
                properties.getCache().getTtl(), properties.getCache().getMaximumSize());
    }

    @Bean
    ValidationRateLimiter validationRateLimiter(ValidationProperties properties) {
        return new ValidationRateLimiter(properties.getRateLimit());
    }

    @Bean
    ClientIpResolver clientIpResolver(ValidationProperties properties) {
        return new ClientIpResolver(properties.getRateLimit().getTrustedProxies());
    }
}
