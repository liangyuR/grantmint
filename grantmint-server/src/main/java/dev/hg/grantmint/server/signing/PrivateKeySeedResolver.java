package dev.hg.grantmint.server.signing;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.function.UnaryOperator;
import org.springframework.stereotype.Component;

/**
 * Resolves the raw 32-byte Ed25519 <em>private</em> seed from a {@code private_key_ref} pointer —
 * the only path by which a signing key enters the running server. The private bytes never live in
 * the database (see {@code ck_signing_keys_ref_is_pointer}); this resolver dereferences the pointer
 * at issuance time and the seed lives in memory only for as long as a signer is being built. 🔒
 *
 * <p>Supported schemes in this build:
 *
 * <ul>
 *   <li>{@code file:/path/to/seed} — a file holding the seed as raw 32 bytes, 64-char hex, or
 *       base64/base64url. On a POSIX filesystem the file MUST NOT be group/other-accessible
 *       (effectively {@code 0600}) or resolution is refused.
 *   <li>{@code env:VAR_NAME} — an environment variable holding the seed in any of the text encodings
 *       above.
 * </ul>
 *
 * <p>The cloud-secret-manager schemes the schema permits ({@code vault:}, {@code awssm:}, {@code
 * gcpsm:}, {@code sops:}) are reserved but not wired in this build; a clear error is raised rather
 * than silently failing. See docs/architecture/ARCHITECTURE.md (issuance flow) and
 * docs/features/LICENSE_TOKEN_FORMAT.md.
 */
@Component
public final class PrivateKeySeedResolver {

    private static final Set<PosixFilePermission> NON_OWNER_PERMISSIONS = EnumSet.of(
            PosixFilePermission.GROUP_READ,
            PosixFilePermission.GROUP_WRITE,
            PosixFilePermission.GROUP_EXECUTE,
            PosixFilePermission.OTHERS_READ,
            PosixFilePermission.OTHERS_WRITE,
            PosixFilePermission.OTHERS_EXECUTE);

    /** Lookup for {@code env:} refs; injectable so tests need not mutate the real environment. */
    private final UnaryOperator<String> environment;

    public PrivateKeySeedResolver() {
        this(System::getenv);
    }

    public PrivateKeySeedResolver(UnaryOperator<String> environment) {
        this.environment = Objects.requireNonNull(environment, "environment");
    }

    /**
     * Dereference {@code privateKeyRef} to the raw 32-byte seed. Callers should wipe the returned
     * array once a signer has been built.
     *
     * @throws SigningKeyException if the ref is malformed, the scheme is unsupported, the target is
     *     missing or too permissive, or the material is not a 32-byte seed
     */
    public byte[] resolveSeed(String privateKeyRef) {
        Objects.requireNonNull(privateKeyRef, "privateKeyRef");
        int colon = privateKeyRef.indexOf(':');
        if (colon <= 0) {
            throw new SigningKeyException("Malformed private_key_ref (expected '<scheme>:<locator>')");
        }
        String scheme = privateKeyRef.substring(0, colon).toLowerCase(Locale.ROOT);
        String locator = privateKeyRef.substring(colon + 1);
        return switch (scheme) {
            case "file" -> fromFile(locator);
            case "env" -> fromEnv(locator);
            case "vault", "awssm", "gcpsm", "sops" -> throw new SigningKeyException("private_key_ref scheme '" + scheme
                    + "' is reserved but not wired in this build; use file: or env:");
            default -> throw new SigningKeyException("Unknown private_key_ref scheme '" + scheme + "'");
        };
    }

    private byte[] fromFile(String locator) {
        Path path = Path.of(locator);
        if (!Files.isRegularFile(path)) {
            throw new SigningKeyException("private_key_ref file does not exist or is not a regular file");
        }
        requireOwnerOnly(path);
        byte[] raw;
        try {
            raw = Files.readAllBytes(path);
        } catch (IOException e) {
            throw new SigningKeyException("Failed to read private_key_ref file", e);
        }
        try {
            return decodeSeed(raw);
        } finally {
            java.util.Arrays.fill(raw, (byte) 0);
        }
    }

    private byte[] fromEnv(String variable) {
        String value = environment.apply(variable);
        if (value == null || value.isBlank()) {
            throw new SigningKeyException("private_key_ref environment variable is unset or blank");
        }
        return decodeSeedText(value);
    }

    /** Refuse a key file readable or writable by group/other (must be effectively {@code 0600}). */
    private static void requireOwnerOnly(Path path) {
        PosixFileAttributeView view = Files.getFileAttributeView(path, PosixFileAttributeView.class);
        if (view == null) {
            return; // non-POSIX filesystem (e.g. Windows) — cannot enforce; rely on OS ACLs
        }
        Set<PosixFilePermission> perms;
        try {
            perms = view.readAttributes().permissions();
        } catch (IOException e) {
            throw new SigningKeyException("Failed to read private_key_ref file permissions", e);
        }
        if (perms.stream().anyMatch(NON_OWNER_PERMISSIONS::contains)) {
            throw new SigningKeyException(
                    "private_key_ref file is group/other-accessible; tighten it to 0600 (owner-only)");
        }
    }

    /** Decode raw file bytes: exactly 32 bytes is a raw seed; anything else is treated as text. */
    private static byte[] decodeSeed(byte[] raw) {
        if (raw.length == Ed25519Keys.RAW_KEY_LENGTH) {
            return raw.clone();
        }
        return decodeSeedText(new String(raw, StandardCharsets.UTF_8));
    }

    /** Decode a textual seed: 64-char hex, or base64url / base64 of the 32-byte seed. */
    private static byte[] decodeSeedText(String text) {
        String trimmed = text.strip();
        if (trimmed.length() == Ed25519Keys.RAW_KEY_LENGTH * 2
                && trimmed.chars().allMatch(PrivateKeySeedResolver::isHex)) {
            return requireSeedLength(HexFormat.of().parseHex(trimmed));
        }
        for (Base64.Decoder decoder : new Base64.Decoder[] {Base64.getUrlDecoder(), Base64.getDecoder()}) {
            try {
                byte[] decoded = decoder.decode(trimmed);
                if (decoded.length == Ed25519Keys.RAW_KEY_LENGTH) {
                    return decoded;
                }
            } catch (IllegalArgumentException ignored) {
                // try the next encoding
            }
        }
        throw new SigningKeyException(
                "private key material is not a 32-byte Ed25519 seed (expected raw 32 bytes, 64-char hex, or base64)");
    }

    private static byte[] requireSeedLength(byte[] seed) {
        if (seed.length != Ed25519Keys.RAW_KEY_LENGTH) {
            throw new SigningKeyException("Ed25519 seed must be " + Ed25519Keys.RAW_KEY_LENGTH + " bytes");
        }
        return seed;
    }

    private static boolean isHex(int c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
}
