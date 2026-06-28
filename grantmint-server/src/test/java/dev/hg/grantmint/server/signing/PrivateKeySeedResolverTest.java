package dev.hg.grantmint.server.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.condition.OS.LINUX;
import static org.junit.jupiter.api.condition.OS.MAC;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.io.TempDir;

/**
 * Resolution of the {@code private_key_ref} pointer into the raw 32-byte seed, across the supported
 * schemes and encodings, plus the security guard rails: owner-only file permissions, reserved-scheme
 * rejection, and rejection of anything that is not a 32-byte seed.
 */
class PrivateKeySeedResolverTest {

    private final byte[] seed = freshSeed();

    @Test
    void resolvesHexEnvRef() {
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(
                name -> Map.of("GM_SEED", HexFormat.of().formatHex(seed)).get(name));
        assertThat(resolver.resolveSeed("env:GM_SEED")).containsExactly(seed);
    }

    @Test
    void resolvesBase64UrlEnvRef() {
        String b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(seed);
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(name -> "GM_SEED".equals(name) ? b64 : null);
        assertThat(resolver.resolveSeed("env:GM_SEED")).containsExactly(seed);
    }

    @Test
    void rejectsUnsetEnvVar() {
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(name -> null);
        assertThatThrownBy(() -> resolver.resolveSeed("env:MISSING"))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("unset or blank");
    }

    @Test
    void rejectsNonSeedMaterial() {
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(name -> "not a key");
        assertThatThrownBy(() -> resolver.resolveSeed("env:X"))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("32-byte Ed25519 seed");
    }

    @Test
    void rejectsMalformedRefAndReservedSchemes() {
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(name -> null);
        assertThatThrownBy(() -> resolver.resolveSeed("no-scheme"))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("Malformed");
        assertThatThrownBy(() -> resolver.resolveSeed("vault:secret/grantmint"))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("not wired");
        assertThatThrownBy(() -> resolver.resolveSeed("smb:share"))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("Unknown");
    }

    @Test
    @EnabledOnOs({LINUX, MAC})
    void resolvesRawBinaryFileWith0600(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("seed.bin");
        Files.write(file, seed);
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(name -> null);
        assertThat(resolver.resolveSeed("file:" + file)).containsExactly(seed);
    }

    @Test
    @EnabledOnOs({LINUX, MAC})
    void resolvesHexTextFileWith0600(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("seed.hex");
        Files.writeString(file, HexFormat.of().formatHex(seed) + "\n", StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(name -> null);
        assertThat(resolver.resolveSeed("file:" + file)).containsExactly(seed);
    }

    @Test
    @EnabledOnOs({LINUX, MAC})
    void refusesGroupOrOtherReadableFile(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("seed.bin");
        Files.write(file, seed);
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(name -> null);
        assertThatThrownBy(() -> resolver.resolveSeed("file:" + file))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("group/other-accessible");
    }

    @Test
    void rejectsMissingFile(@TempDir Path dir) {
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(name -> null);
        assertThatThrownBy(() -> resolver.resolveSeed("file:" + dir.resolve("nope.bin")))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("does not exist");
    }

    private static byte[] freshSeed() {
        KeyPair pair = Ed25519Keys.generate(new SecureRandom());
        return Ed25519Keys.encodePrivateKey(pair.getPrivate());
    }
}
