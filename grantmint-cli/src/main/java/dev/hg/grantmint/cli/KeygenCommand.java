package dev.hg.grantmint.cli;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * {@code grantmint keygen} — generate a fresh Ed25519 signing keypair.
 *
 * <p>The private seed is written to disk as lowercase hex with owner-only (0600) permissions, set
 * atomically at creation (never written world-readable and then chmod'd). The seed is never printed
 * — only the public key (safe to distribute/embed) goes to stdout, alongside the {@code file:}
 * pointer the server's {@code private_key_ref} config expects (see {@code
 * dev.hg.grantmint.server.signing.PrivateKeySeedResolver}, which requires exactly this owner-only
 * file mode).
 */
@Command(name = "keygen", description = "Generate an Ed25519 signing keypair.")
public final class KeygenCommand implements Callable<Integer> {

    @Option(
            names = {"--out"},
            required = true,
            description = "File to write the private key seed to (lowercase hex, mode 0600). Must not already exist.")
    Path out;

    @Override
    public Integer call() {
        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());
        byte[] seed = Ed25519Keys.encodePrivateKey(keyPair.getPrivate());
        try {
            writeSeedFile(seed);
        } catch (UnsupportedOperationException e) {
            System.err.println("error: " + out
                    + " is not on a POSIX filesystem, so 0600 permissions cannot be enforced; refusing to "
                    + "write the private key.");
            return 1;
        } catch (FileAlreadyExistsException e) {
            System.err.println("error: " + out + " already exists; refusing to overwrite a signing key.");
            return 1;
        } catch (IOException e) {
            System.err.println("error: failed to write " + out + ": " + e.getMessage());
            return 1;
        } finally {
            Arrays.fill(seed, (byte) 0);
        }

        byte[] publicKey = Ed25519Keys.encodePublicKey(keyPair.getPublic());
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey);
        System.out.println("Public key (base64): " + publicKeyBase64);
        System.out.println("Private key seed written to: " + out.toAbsolutePath() + " (mode 0600)");
        System.out.println("Server private_key_ref: file:" + out.toAbsolutePath());
        System.out.println("Never share, print, or commit the private key file.");
        return 0;
    }

    /**
     * Create the file with owner-only permissions baked into the creation call itself (no
     * create-then-chmod window where the seed is briefly world-readable), then write the hex seed.
     */
    private void writeSeedFile(byte[] seed) throws IOException {
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
        FileAttribute<Set<PosixFilePermission>> attribute = PosixFilePermissions.asFileAttribute(ownerOnly);
        Path created = Files.createFile(out, attribute);
        Files.write(created, HexFormat.of().formatHex(seed).getBytes(StandardCharsets.US_ASCII));
    }
}
