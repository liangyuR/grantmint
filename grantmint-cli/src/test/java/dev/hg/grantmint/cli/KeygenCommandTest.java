package dev.hg.grantmint.cli;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import dev.hg.grantmint.core.crypto.Ed25519Keys;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

class KeygenCommandTest {

    private final PrintStream originalOut = System.out;
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    @BeforeEach
    void redirectOut() {
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
    }

    @AfterEach
    void restoreOut() {
        System.setOut(originalOut);
    }

    @Test
    void writesOwnerOnlyKeyFileAndPrintsARoundTrippablePublicKey(@TempDir Path dir) throws Exception {
        Path keyFile = dir.resolve("signing.key");

        int exitCode = new CommandLine(new GrantmintCli()).execute("keygen", "--out", keyFile.toString());

        assertThat(exitCode).isZero();

        Set<java.nio.file.attribute.PosixFilePermission> perms = Files.getPosixFilePermissions(keyFile);
        assertThat(PosixFilePermissions.toString(perms)).isEqualTo("rw-------");

        String hexSeed = Files.readString(keyFile, StandardCharsets.US_ASCII).strip();
        assertThat(hexSeed).matches("[0-9a-f]{64}");
        byte[] seed = HexFormat.of().parseHex(hexSeed);
        assertThat(Ed25519Keys.decodePrivateKey(seed)).isNotNull();

        String printed = out.toString(StandardCharsets.UTF_8);
        String prefix = "Public key (base64): ";
        String publicKeyBase64 = printed.lines()
                .filter(line -> line.startsWith(prefix))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no public key line in output:\n" + printed))
                .substring(prefix.length());

        byte[] rawPublicKey = Base64.getDecoder().decode(publicKeyBase64);
        PublicKey publicKey = Ed25519Keys.decodePublicKey(rawPublicKey);
        assertThat(publicKey).isNotNull();

        // The private key material must never be printed.
        assertThat(printed).doesNotContain(hexSeed);
    }

    @Test
    void refusesToWriteWhereOwnerOnlyPermissionsCannotBeEnforced() throws Exception {
        // A non-POSIX filesystem (Jimfs in Windows configuration) cannot take the 0600 attribute,
        // so keygen must fail closed rather than write the seed with unknown permissions.
        PrintStream originalErr = System.err;
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
        try (FileSystem windows = Jimfs.newFileSystem(Configuration.windows())) {
            Path keyFile = windows.getPath("C:\\").resolve("signing.key");
            KeygenCommand command = new KeygenCommand();
            command.out = keyFile;

            assertThat(command.call()).isEqualTo(1);
            assertThat(Files.exists(keyFile)).isFalse();
            assertThat(err.toString(StandardCharsets.UTF_8)).contains("not on a POSIX filesystem");
            assertThat(out.toString(StandardCharsets.UTF_8)).doesNotContain("Public key");
        } finally {
            System.setErr(originalErr);
        }
    }

    @Test
    void refusesToOverwriteAnExistingFile(@TempDir Path dir) throws Exception {
        Path keyFile = dir.resolve("signing.key");
        Files.writeString(keyFile, "not-a-key");

        int exitCode = new CommandLine(new GrantmintCli()).execute("keygen", "--out", keyFile.toString());

        assertThat(exitCode).isNotZero();
        assertThat(Files.readString(keyFile)).isEqualTo("not-a-key");
    }
}
