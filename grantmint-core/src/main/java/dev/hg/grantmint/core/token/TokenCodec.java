package dev.hg.grantmint.core.token;

import dev.hg.grantmint.core.codec.Base64Url;
import dev.hg.grantmint.core.codec.CanonicalJson;
import dev.hg.grantmint.core.codec.JsonParseException;
import java.util.Map;

/**
 * Encodes/decodes token segments between the typed model and the canonical base64url wire form.
 *
 * <p>Encoding goes {@code value → canonical JSON bytes → base64url}. Decoding is the inverse and is
 * defensive: any Base64 or JSON error becomes a {@link MalformedTokenException} so verification can
 * treat a garbage token as untrusted input rather than crashing.
 */
public final class TokenCodec {

    private TokenCodec() {}

    /** Encode the header as segment A. */
    public static String encodeHeader(TokenHeader header) {
        return Base64Url.encode(CanonicalJson.serialize(header.toMap()));
    }

    /** Encode the payload as segment B. */
    public static String encodePayload(TokenPayload payload) {
        return Base64Url.encode(CanonicalJson.serialize(payload.toClaimMap()));
    }

    /** Decode segment A into a header. */
    public static TokenHeader decodeHeader(String segment) {
        return TokenHeader.fromMap(decodeObject(segment, "header"));
    }

    /** Decode segment B into a payload. */
    public static TokenPayload decodePayload(String segment) {
        return TokenPayload.fromClaimMap(decodeObject(segment, "payload"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> decodeObject(String segment, String what) {
        try {
            Object parsed = CanonicalJson.parse(Base64Url.decode(segment));
            if (!(parsed instanceof Map<?, ?> map)) {
                throw new MalformedTokenException("Token " + what + " is not a JSON object");
            }
            return (Map<String, Object>) map;
        } catch (IllegalArgumentException | JsonParseException e) {
            // Base64 decode failure or malformed JSON — an untrusted, malformed token.
            throw new MalformedTokenException("Token " + what + " is not valid base64url JSON", e);
        }
    }
}
