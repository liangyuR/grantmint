package dev.hg.grantmint.server.signing;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Exec seam for the {@code sops:} {@code private_key_ref} scheme. Tests supply a lambda; production
 * runs the real process. Stdout is the decrypted material and is treated as secret; stderr is only
 * surfaced (truncated) on failure.
 */
@FunctionalInterface
interface CommandRunner {

    byte[] run(List<String> argv);

    static CommandRunner process() {
        return argv -> {
            try {
                Process process = new ProcessBuilder(argv).start();
                byte[] stdout = process.getInputStream().readAllBytes();
                byte[] stderr = process.getErrorStream().readAllBytes();
                if (!process.waitFor(30, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    throw new SigningKeyException("'" + argv.get(0) + "' timed out after 30s");
                }
                if (process.exitValue() != 0) {
                    String detail = new String(stderr, StandardCharsets.UTF_8).strip();
                    throw new SigningKeyException("'" + argv.get(0) + "' exited " + process.exitValue()
                            + (detail.isEmpty() ? "" : ": " + detail.substring(0, Math.min(detail.length(), 200))));
                }
                return stdout;
            } catch (IOException e) {
                throw new SigningKeyException("Failed to run '" + argv.get(0) + "' (is it installed?)", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new SigningKeyException("'" + argv.get(0) + "' interrupted", e);
            }
        };
    }
}
