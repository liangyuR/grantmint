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

    /** Decode padding-free URL-safe Base64 (the decoder also tolerates padding if present). */
    public static byte[] decode(String text) {
        Objects.requireNonNull(text, "text");
        return DECODER.decode(text);
    }
}
