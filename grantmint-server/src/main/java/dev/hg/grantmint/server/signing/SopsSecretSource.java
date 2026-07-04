package dev.hg.grantmint.server.signing;

import java.util.ArrayList;
import java.util.List;
import java.util.function.UnaryOperator;

/**
 * {@code sops:<path>[#<key>]} — decrypt a <a href="https://github.com/getsops/sops">SOPS</a> file by
 * exec'ing the {@code sops} binary ({@code SOPS_BINARY} overrides the executable). Without a
 * fragment the whole decrypted file is the seed material; with one, the named top-level key is
 * extracted ({@code --extract}). Key discovery (age/KMS/PGP) is whatever the sops binary is
 * configured for — this class never sees key-encryption material.
 */
final class SopsSecretSource {

    private final CommandRunner runner;
    private final UnaryOperator<String> environment;

    SopsSecretSource(CommandRunner runner, UnaryOperator<String> environment) {
        this.runner = runner;
        this.environment = environment;
    }

    byte[] fetch(String locator) {
        String path = locator;
        String key = null;
        int hash = locator.lastIndexOf('#');
        if (hash >= 0) {
            path = locator.substring(0, hash);
            key = locator.substring(hash + 1);
        }
        if (path.isBlank()) {
            throw new SigningKeyException("sops: ref is missing the file path");
        }
        String binary = environment.apply("SOPS_BINARY");
        List<String> argv = new ArrayList<>();
        argv.add(binary == null || binary.isBlank() ? "sops" : binary);
        argv.add("--decrypt");
        if (key != null) {
            argv.add("--extract");
            argv.add("[\"" + key.replace("\\", "\\\\").replace("\"", "\\\"") + "\"]");
        }
        argv.add(path);
        return runner.run(argv);
    }
}
