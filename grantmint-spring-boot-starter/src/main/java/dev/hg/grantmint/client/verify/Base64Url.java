package dev.hg.grantmint.client.verify;

import java.util.Base64;

/**
 * Strict, unpadded base64url decoding for token segments. The wire format is URL-safe alphabet
 * WITHOUT padding; a {@code =}-padded or otherwise non-canonical segment is malformed and must be
 * rejected, not repaired — every verifier (Java, Swift, Go) has to read the same bytes or refuse.
 * See docs/testing/CROSS_VERIFIER_FIXTURES.md.
 *
 * <p>Fresh Apache-2.0 code: this module must not depend on the AGPL {@code grantmint-core};
 * behavioural parity is enforced by the cross-verifier fixture tests instead.
 */
final class Base64Url {

    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    /** Decode a segment, rejecting padding, standard-alphabet characters, and anything non-canonical. */
    static byte[] decodeStrict(String segment) {
        if (segment.isEmpty() || segment.indexOf('=') >= 0 || segment.indexOf('+') >= 0 || segment.indexOf('/') >= 0) {
            throw new IllegalArgumentException("segment is not unpadded base64url");
        }
        // A single leftover sextet (length % 4 == 1) can never encode whole bytes.
        if (segment.length() % 4 == 1) {
            throw new IllegalArgumentException("segment has impossible base64url length");
        }
        byte[] decoded = DECODER.decode(segment); // throws IllegalArgumentException on bad chars
        // Canonicality: re-encoding must reproduce the exact segment (rejects non-zero trailing bits).
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(segment)) {
            throw new IllegalArgumentException("segment is not canonical base64url");
        }
        return decoded;
    }

    private Base64Url() {}
}
