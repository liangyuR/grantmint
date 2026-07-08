package dev.hg.grantmint.core.token;

import dev.hg.grantmint.core.codec.Base64Url;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * The three wire segments of a token: {@code <header>.<payload>.<signature>}, each URL-safe Base64.
 *
 * <p>This is a structural value — it holds the segments exactly as transmitted so that verification
 * can rebuild the signing input from the <em>received</em> bytes (never a re-serialization, which
 * could differ and break the signature). See docs/features/LICENSE_TOKEN_FORMAT.md.
 */
public record SignedToken(String headerSegment, String payloadSegment, String signatureSegment) {

    public SignedToken {
        Objects.requireNonNull(headerSegment, "headerSegment");
        Objects.requireNonNull(payloadSegment, "payloadSegment");
        Objects.requireNonNull(signatureSegment, "signatureSegment");
    }

    /** The full {@code A.B.C} token string. */
    public String serialize() {
        return headerSegment + "." + payloadSegment + "." + signatureSegment;
    }

    /**
     * Split a token string into its three segments.
     *
     * @throws MalformedTokenException if the input is not exactly three non-empty dot-separated parts
     */
    public static SignedToken parse(String token) {
        Objects.requireNonNull(token, "token");
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            throw new MalformedTokenException("Token must be three non-empty dot-separated segments");
        }
        return new SignedToken(parts[0], parts[1], parts[2]);
    }

    /** The ASCII bytes Ed25519 signs/verifies over: {@code header + "." + payload}. */
    public byte[] signingInput() {
        return (headerSegment + "." + payloadSegment).getBytes(StandardCharsets.US_ASCII);
    }

    /** The decoded payload bytes — segment decodability is part of structural well-formedness. */
    public byte[] payloadBytes() {
        return Base64Url.decode(payloadSegment);
    }

    /** The decoded 64-byte signature. */
    public byte[] signatureBytes() {
        return Base64Url.decode(signatureSegment);
    }
}
