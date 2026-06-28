package dev.hg.grantmint.server.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * Low-level secret hygiene for the API-key and admin-session schemes.
 *
 * <p>API keys and session tokens are high-entropy random strings, so a single SHA-256 is a
 * sufficient at-rest representation (no need for Argon2's deliberate slowness — that is reserved
 * for low-entropy admin <em>passwords</em>). Lookups hash the presented secret and compare the
 * stored hash in constant time to deny timing oracles. The plaintext secret is generated here,
 * returned to the caller exactly once, and never persisted or logged.
 *
 * <p>See docs/features/ADMIN_AND_API_AUTH.md (Key storage and rotation).
 */
public final class Secrets {

    /** Number of random bytes behind every API key / session token: 256 bits of entropy. */
    public static final int TOKEN_BYTES = 32;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of(); // lowercase, unseparated

    private Secrets() {}

    /** Generate {@link #TOKEN_BYTES} of cryptographic randomness, hex-encoded (lowercase). */
    public static String randomTokenHex() {
        byte[] bytes = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(bytes);
        return HEX.formatHex(bytes);
    }

    /** SHA-256 of the UTF-8 bytes of {@code value}, hex-encoded (lowercase). */
    public static String sha256Hex(String value) {
        byte[] digest = sha256().digest(value.getBytes(StandardCharsets.UTF_8));
        return HEX.formatHex(digest);
    }

    /**
     * Constant-time comparison of two hex-encoded hashes. Returns {@code false} on any malformed
     * input rather than throwing, so a crafted value can never distinguish itself by exception
     * timing or type.
     */
    public static boolean constantTimeEqualsHex(String aHex, String bHex) {
        if (aHex == null || bHex == null) {
            return false;
        }
        byte[] a;
        byte[] b;
        try {
            a = HEX.parseHex(aHex);
            b = HEX.parseHex(bHex);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        return MessageDigest.isEqual(a, b);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by every JRE; absence is a broken platform.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
