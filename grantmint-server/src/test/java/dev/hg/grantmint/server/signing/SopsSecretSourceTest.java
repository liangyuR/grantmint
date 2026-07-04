package dev.hg.grantmint.server.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

/** The {@code sops:} scheme: argv construction, extraction fragments, and the real process runner. */
class SopsSecretSourceTest {

    private static final SecretHttp NO_HTTP = (method, uri, headers, body) -> {
        throw new AssertionError("unexpected HTTP call");
    };
    private static final UnaryOperator<String> NO_ENV = name -> null;

    private final byte[] seed = Ed25519Keys.encodePrivateKey(
            Ed25519Keys.generate(new SecureRandom()).getPrivate());

    @Test
    void decryptsWholeFile() {
        AtomicReference<List<String>> argv = new AtomicReference<>();
        CommandRunner runner = command -> {
            argv.set(command);
            return (HexFormat.of().formatHex(seed) + "\n").getBytes(StandardCharsets.UTF_8);
        };
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(NO_ENV, NO_HTTP, runner, Clock.systemUTC());
        assertThat(resolver.resolveSeed("sops:/etc/grantmint/seed.enc")).containsExactly(seed);
        assertThat(argv.get()).containsExactly("sops", "--decrypt", "/etc/grantmint/seed.enc");
    }

    @Test
    void extractsNamedKeyAndHonorsBinaryOverride() {
        AtomicReference<List<String>> argv = new AtomicReference<>();
        CommandRunner runner = command -> {
            argv.set(command);
            return HexFormat.of().formatHex(seed).getBytes(StandardCharsets.UTF_8);
        };
        UnaryOperator<String> env = name -> "SOPS_BINARY".equals(name) ? "/opt/sops/bin/sops" : null;
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(env, NO_HTTP, runner, Clock.systemUTC());
        assertThat(resolver.resolveSeed("sops:/etc/grantmint/secrets.yaml#signing_seed"))
                .containsExactly(seed);
        assertThat(argv.get())
                .containsExactly(
                        "/opt/sops/bin/sops",
                        "--decrypt",
                        "--extract",
                        "[\"signing_seed\"]",
                        "/etc/grantmint/secrets.yaml");
    }

    @Test
    void realRunnerCapturesStdoutAndFailsClosed() {
        CommandRunner runner = CommandRunner.process();
        assertThat(runner.run(List.of("/bin/echo", "-n", "hello")))
                .asString(StandardCharsets.UTF_8)
                .isEqualTo("hello");
        assertThatThrownBy(() -> runner.run(List.of("/usr/bin/false")))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("exited 1");
        assertThatThrownBy(() -> runner.run(List.of("/no/such/binary")))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("is it installed");
    }
}
