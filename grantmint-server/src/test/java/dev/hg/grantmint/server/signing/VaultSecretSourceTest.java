package dev.hg.grantmint.server.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

/** The {@code vault:} scheme: request shape, KV v1/v2 response shapes, field selection, env guards. */
class VaultSecretSourceTest {

    private static final CommandRunner NO_EXEC = argv -> {
        throw new AssertionError("unexpected exec");
    };

    private final byte[] seed = Ed25519Keys.encodePrivateKey(
            Ed25519Keys.generate(new SecureRandom()).getPrivate());
    private final String seedHex = HexFormat.of().formatHex(seed);

    private final UnaryOperator<String> env = name -> Map.of(
                    "VAULT_ADDR", "https://vault.example.com:8200",
                    "VAULT_TOKEN", "s.unit-test-token")
            .get(name);

    @Test
    void readsKvV2FieldWithTokenHeader() {
        AtomicReference<String> requestedUri = new AtomicReference<>();
        AtomicReference<Map<String, String>> sentHeaders = new AtomicReference<>();
        SecretHttp http = (method, uri, headers, body) -> {
            assertThat(method).isEqualTo("GET");
            requestedUri.set(uri.toString());
            sentHeaders.set(headers);
            return new SecretHttp.Response(
                    200,
                    ("{\"data\":{\"data\":{\"seed\":\"" + seedHex + "\",\"note\":\"x\"}}}")
                            .getBytes(StandardCharsets.UTF_8));
        };
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(env, http, NO_EXEC, Clock.systemUTC());

        assertThat(resolver.resolveSeed("vault:secret/data/grantmint/signing#seed"))
                .containsExactly(seed);
        assertThat(requestedUri.get()).isEqualTo("https://vault.example.com:8200/v1/secret/data/grantmint/signing");
        assertThat(sentHeaders.get()).containsEntry("X-Vault-Token", "s.unit-test-token");
    }

    @Test
    void readsKvV1SingleFieldWithoutFragment() {
        SecretHttp http = (method, uri, headers, body) -> new SecretHttp.Response(
                200, ("{\"data\":{\"seed\":\"" + seedHex + "\"}}").getBytes(StandardCharsets.UTF_8));
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(env, http, NO_EXEC, Clock.systemUTC());
        assertThat(resolver.resolveSeed("vault:secret/grantmint")).containsExactly(seed);
    }

    @Test
    void requiresFragmentWhenSecretHasMultipleFields() {
        SecretHttp http = (method, uri, headers, body) ->
                new SecretHttp.Response(200, ("{\"data\":{\"a\":\"1\",\"b\":\"2\"}}").getBytes(StandardCharsets.UTF_8));
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(env, http, NO_EXEC, Clock.systemUTC());
        assertThatThrownBy(() -> resolver.resolveSeed("vault:secret/grantmint"))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("multiple fields");
    }

    @Test
    void surfacesNonOkStatusWithoutBody() {
        SecretHttp http = (method, uri, headers, body) ->
                new SecretHttp.Response(403, "{\"errors\":[\"permission denied\"]}".getBytes(StandardCharsets.UTF_8));
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(env, http, NO_EXEC, Clock.systemUTC());
        assertThatThrownBy(() -> resolver.resolveSeed("vault:secret/grantmint#seed"))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("HTTP 403");
    }

    @Test
    void requiresVaultAddrAndToken() {
        SecretHttp http = (method, uri, headers, body) -> {
            throw new AssertionError("must not call Vault without config");
        };
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(name -> null, http, NO_EXEC, Clock.systemUTC());
        assertThatThrownBy(() -> resolver.resolveSeed("vault:secret/grantmint#seed"))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("VAULT_ADDR");
    }
}
