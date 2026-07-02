package dev.hg.grantmint.core.codec;

import java.util.Base64;
import java.util.Objects;

/**
 * URL-safe Base64 without padding — the alphabet used for all three token segments.
 *
 * <p>The {@code -}/{@code _} alphabet with stripped {@code =} keeps the whole token safe inside URLs,
 * HTTP headers, and QR codes. This is part of the wire contract; the Swift and Go verifiers use the
 * same alphabet (see docs/features/LICENSE_TOKEN_FORMAT.md).
 */
public final class Base64Url {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private Base64Url() {}

    /** Encode bytes to padding-free URL-safe Base64. */
    public static String encode(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        return ENCODER.encodeToString(bytes);
    }

    /**
     * Decode padding-free URL-safe Base64, accepting only the canonical encoding.
     *
     * <p>Padding and canonicality are part of the wire contract: tokens are emitted without {@code =},
     * and any alternate encoding of the same bytes — a padded segment, or a final character with
     * non-zero unused trailing bits (the JDK decoder silently ignores them, so {@code "AC"} and
     * {@code "AA"} decode identically) — would break byte-for-byte parity with the starter, Swift, and
     * Go verifiers. Every alternate encoding is rejected ({@link IllegalArgumentException}) rather than
     * silently accepted, which callers surface as a malformed token. The check is re-encode-and-compare:
     * exactly one text form decodes to any byte string.
     */
    public static byte[] decode(String text) {
        Objects.requireNonNull(text, "text");
        if (text.indexOf('=') >= 0) {
            throw new IllegalArgumentException("Base64URL segment must not contain '=' padding");
        }
        byte[] decoded = DECODER.decode(text);
        if (!ENCODER.encodeToString(decoded).equals(text)) {
            throw new IllegalArgumentException("Base64URL segment is not canonical (non-zero trailing bits)");
        }
        return decoded;
    }
}
