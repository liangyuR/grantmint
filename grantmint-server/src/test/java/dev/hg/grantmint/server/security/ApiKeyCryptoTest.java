package dev.hg.grantmint.server.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Fast, framework-free checks on the API-key crypto hygiene: hashing determinism, constant-time
 * comparison robustness, randomness, and namespacing. These back the security claims that the
 * stored hash is not the secret and that distinct keys never collide.
 */
class ApiKeyCryptoTest {

    private final ApiKeyGenerator generator = new ApiKeyGenerator();

    @Test
    void sha256IsDeterministicAndNotTheInput() {
        String secret = "gm_live_deadbeef";
        assertThat(Secrets.sha256Hex(secret)).isEqualTo(Secrets.sha256Hex(secret));
        assertThat(Secrets.sha256Hex(secret)).isNotEqualTo(secret);
        assertThat(Secrets.sha256Hex(secret)).hasSize(64); // 32 bytes hex
    }

    @Test
    void constantTimeCompareMatchesEqualAndRejectsDifferentOrMalformed() {
        String hash = Secrets.sha256Hex("a");
        assertThat(Secrets.constantTimeEqualsHex(hash, hash)).isTrue();
        assertThat(Secrets.constantTimeEqualsHex(hash, Secrets.sha256Hex("b"))).isFalse();
        assertThat(Secrets.constantTimeEqualsHex(hash, null)).isFalse();
        assertThat(Secrets.constantTimeEqualsHex(hash, "not-hex-zzzz")).isFalse();
    }

    @Test
    void generatedKeysAreUniqueWithCorrectNamespaceAndStoredAsHash() {
        GeneratedApiKey live = generator.generate(ApiKeyScope.ISSUANCE, ApiKeyEnvironment.LIVE);
        GeneratedApiKey test = generator.generate(ApiKeyScope.ISSUANCE, ApiKeyEnvironment.TEST);
        GeneratedApiKey val = generator.generate(ApiKeyScope.VALIDATION, ApiKeyEnvironment.LIVE);

        assertThat(live.plaintext()).startsWith("gm_live_");
        assertThat(test.plaintext()).startsWith("gm_test_");
        assertThat(val.plaintext()).startsWith("gm_val_");

        // The stored hash is the SHA-256 of the plaintext, never the plaintext itself.
        assertThat(live.keyHash()).isEqualTo(Secrets.sha256Hex(live.plaintext()));
        assertThat(live.keyHash()).isNotEqualTo(live.plaintext());

        // Two mints never collide.
        GeneratedApiKey live2 = generator.generate(ApiKeyScope.ISSUANCE, ApiKeyEnvironment.LIVE);
        assertThat(live.plaintext()).isNotEqualTo(live2.plaintext());
        assertThat(live.keyHash()).isNotEqualTo(live2.keyHash());

        // The display prefix is a leading slice of the plaintext, not the whole secret.
        assertThat(live.plaintext()).startsWith(live.keyPrefix());
        assertThat(live.keyPrefix()).hasSize(ApiKeyGenerator.PREFIX_LENGTH);
    }
}
