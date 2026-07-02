package dev.hg.grantmint.client.verify;

import dev.hg.grantmint.client.verify.TokenVerificationException.Reason;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

/**
 * The starter's self-contained offline verifier — signature, header pinning, and temporal window
 * against the embedded Ed25519 public key, with <b>no network and no AGPL code</b>. This is fresh
 * Apache-2.0 code whose behaviour is pinned byte-for-byte to the reference verifier by the
 * cross-verifier fixtures (docs/testing/CROSS_VERIFIER_FIXTURES.md); the verification algorithm is
 * the numbered contract in that document:
 *
 * <ol>
 *   <li>exactly three non-empty dot-separated segments, each strict unpadded base64url;
 *   <li>header pinned to {@code alg=EdDSA, crv=Ed25519, typ=GMT} <em>before</em> any signature
 *       work — this closes JWT algorithm confusion;
 *   <li>Ed25519 signature over the ASCII bytes of the <em>received</em>
 *       {@code headerSegment + "." + payloadSegment} (never re-serialized);
 *   <li>only then parse the payload: {@code ver == 1}; {@code exp} is a required claim whose value
 *       may be null (perpetual) — absence is malformed; {@code nbf} is genuinely optional;
 *       {@code now >= exp} is expired (exp exclusive), {@code now < nbf} not yet valid.
 * </ol>
 */
public final class OfflineTokenVerifier {

    private final PublicKey publicKey;
    private final Clock clock;

    /** @param base64PublicKey standard base64 of the 32-byte raw RFC 8032 Ed25519 public key */
    public OfflineTokenVerifier(String base64PublicKey) {
        this(base64PublicKey, Clock.systemUTC());
    }

    /** Clock seam so the temporal window is testable deterministically. */
    public OfflineTokenVerifier(String base64PublicKey, Clock clock) {
        this.publicKey = decodeRawPublicKey(Base64.getDecoder().decode(base64PublicKey));
        this.clock = clock;
    }

    /** Verify at the configured clock's now. */
    public VerifiedToken verify(String token) {
        return verifyAt(token, clock.instant());
    }

    /**
     * Verify the token as of {@code now}.
     *
     * @throws TokenVerificationException when the token is malformed, forged, expired, or not yet
     *     valid — the reason says which
     */
    public VerifiedToken verifyAt(String token, Instant now) {
        if (token == null || token.isBlank()) {
            throw malformed("token is empty");
        }
        String[] segments = token.split("\\.", -1);
        if (segments.length != 3 || segments[0].isEmpty() || segments[1].isEmpty() || segments[2].isEmpty()) {
            throw malformed("token must be three non-empty dot-separated segments");
        }
        byte[] headerBytes;
        byte[] signature;
        try {
            headerBytes = Base64Url.decodeStrict(segments[0]);
            Base64Url.decodeStrict(segments[1]); // payload decodability is part of well-formedness
            signature = Base64Url.decodeStrict(segments[2]);
        } catch (IllegalArgumentException bad) {
            throw malformed("segment is not strict unpadded base64url");
        }

        pinHeader(headerBytes);

        if (signature.length != 64) {
            throw new TokenVerificationException(Reason.INVALID_SIGNATURE, "signature is not 64 bytes");
        }
        byte[] signingInput = (segments[0] + "." + segments[1]).getBytes(StandardCharsets.US_ASCII);
        if (!verifySignature(signingInput, signature)) {
            throw new TokenVerificationException(Reason.INVALID_SIGNATURE, "Ed25519 signature mismatch");
        }

        // Claims are trusted only past this point — the signature has spoken.
        return checkClaims(parsePayload(segments[1]), now);
    }

    private static void pinHeader(byte[] headerBytes) {
        Map<String, Object> header;
        try {
            header = StrictJson.parseObject(new String(headerBytes, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException bad) {
            throw malformed("header is not strict JSON");
        }
        if (!"EdDSA".equals(header.get("alg"))
                || !"Ed25519".equals(header.get("crv"))
                || !"GMT".equals(header.get("typ"))) {
            throw new TokenVerificationException(
                    Reason.INVALID_SIGNATURE, "header is not pinned to alg=EdDSA, crv=Ed25519, typ=GMT");
        }
    }

    private boolean verifySignature(byte[] signingInput, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(signingInput);
            return verifier.verify(signature);
        } catch (Exception cryptoFailure) {
            return false;
        }
    }

    private static Map<String, Object> parsePayload(String payloadSegment) {
        try {
            return StrictJson.parseObject(new String(Base64Url.decodeStrict(payloadSegment), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException bad) {
            throw malformed("payload is not strict JSON");
        }
    }

    private static VerifiedToken checkClaims(Map<String, Object> claims, Instant now) {
        if (!(claims.get("ver") instanceof Long version) || version != 1L) {
            throw malformed("unsupported or missing token version");
        }
        // exp is REQUIRED on the wire; its value may be null (perpetual). Absence is malformed —
        // never silently perpetual (CROSS_VERIFIER_FIXTURES.md, perpetual licenses note).
        if (!claims.containsKey("exp")) {
            throw malformed("exp claim is required (null means perpetual, absent is invalid)");
        }
        Long exp = optionalEpoch(claims, "exp");
        Long nbf = optionalEpoch(claims, "nbf");
        Long iat = optionalEpoch(claims, "iat");

        if (nbf != null && now.getEpochSecond() < nbf) {
            throw new TokenVerificationException(Reason.NOT_YET_VALID, "token not valid before " + nbf);
        }
        if (exp != null && now.getEpochSecond() >= exp) {
            throw new TokenVerificationException(Reason.EXPIRED, "token expired at " + exp);
        }

        Map<String, Object> holder = optionalObject(claims, "hld");
        return new VerifiedToken(
                requiredString(claims, "kid"),
                requiredString(claims, "lid"),
                requiredString(claims, "prd"),
                optionalString(claims, "pol"),
                holder == null ? null : optionalString(holder, "n"),
                holder == null ? null : optionalString(holder, "e"),
                iat == null ? null : Instant.ofEpochSecond(iat),
                nbf == null ? null : Instant.ofEpochSecond(nbf),
                exp == null ? null : Instant.ofEpochSecond(exp),
                optionalObject(claims, "ent"),
                claims.get("seat") instanceof Long seat ? seat : null,
                optionalObject(claims, "con"));
    }

    private static Long optionalEpoch(Map<String, Object> claims, String key) {
        Object value = claims.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof Long epoch)) {
            throw malformed(key + " must be an integer epoch second");
        }
        return epoch;
    }

    private static String requiredString(Map<String, Object> claims, String key) {
        if (!(claims.get(key) instanceof String value) || value.isEmpty()) {
            throw malformed("missing required claim: " + key);
        }
        return value;
    }

    private static String optionalString(Map<String, Object> claims, String key) {
        return claims.get(key) instanceof String value ? value : null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> optionalObject(Map<String, Object> claims, String key) {
        Object value = claims.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof Map)) {
            throw malformed(key + " must be a JSON object");
        }
        return (Map<String, Object>) value;
    }

    /** RFC 8032: 32 little-endian bytes; bit 255 is the x-parity, the rest the y-coordinate. */
    private static PublicKey decodeRawPublicKey(byte[] raw) {
        if (raw.length != 32) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 raw bytes");
        }
        boolean xOdd = (raw[31] & 0x80) != 0;
        byte[] yLittleEndian = raw.clone();
        yLittleEndian[31] &= 0x7F;
        byte[] yBigEndian = new byte[32];
        for (int i = 0; i < 32; i++) {
            yBigEndian[i] = yLittleEndian[31 - i];
        }
        try {
            return KeyFactory.getInstance("Ed25519")
                    .generatePublic(new EdECPublicKeySpec(
                            NamedParameterSpec.ED25519, new EdECPoint(xOdd, new BigInteger(1, yBigEndian))));
        } catch (Exception invalidKey) {
            throw new IllegalArgumentException("invalid Ed25519 public key", invalidKey);
        }
    }

    private static TokenVerificationException malformed(String message) {
        return new TokenVerificationException(Reason.MALFORMED, message);
    }
}
