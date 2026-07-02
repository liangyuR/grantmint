package dev.hg.grantmint.cli;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Resolves a {@code --token} argument shared by {@code verify} and {@code inspect}: either the
 * token literal, or {@code @path/to/file} to read it from disk (whitespace-trimmed either way, since
 * a token written to a file commonly picks up a trailing newline).
 */
final class TokenInput {

    private static final String FILE_PREFIX = "@";

    private TokenInput() {}

    static String resolve(String arg) throws IOException {
        if (arg.startsWith(FILE_PREFIX)) {
            Path path = Path.of(arg.substring(FILE_PREFIX.length()));
            return Files.readString(path, StandardCharsets.UTF_8).strip();
        }
        return arg.strip();
    }
}
