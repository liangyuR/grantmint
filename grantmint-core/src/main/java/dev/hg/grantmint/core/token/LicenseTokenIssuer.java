package dev.hg.grantmint.core.token;

import dev.hg.grantmint.core.codec.Base64Url;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import java.util.Objects;

/**
 * Builds and signs license tokens — the construction half of the wire spec.
 *
 * <p>Given a {@link TokenPayload}, the issuer stamps the canonical header for its signer's
 * signing-key id, encodes both segments to canonical base64url, signs the ASCII signing input
 * ({@code A + "." + B}), and assembles the {@link SignedToken}. It holds an {@link Ed25519Signer} and
 * therefore the private key — this type lives only server-side.
 */
public final class LicenseTokenIssuer {

    private final Ed25519Signer signer;

    public LicenseTokenIssuer(Ed25519Signer signer) {
        this.signer = Objects.requireNonNull(signer, "signer");
    }

    /** Build and sign a token from the given claims. */
    public SignedToken issue(TokenPayload payload) {
        Objects.requireNonNull(payload, "payload");
        TokenHeader header = TokenHeader.forSigningKey(signer.signingKeyId());
        String headerSegment = TokenCodec.encodeHeader(header);
        String payloadSegment = TokenCodec.encodePayload(payload);
        SignedToken unsigned = new SignedToken(headerSegment, payloadSegment, "");
        byte[] signature = signer.sign(unsigned.signingInput());
        return new SignedToken(headerSegment, payloadSegment, Base64Url.encode(signature));
    }

    /** Build, sign, and serialize a token in one call. */
    public String sign(TokenPayload payload) {
        return issue(payload).serialize();
    }
}
