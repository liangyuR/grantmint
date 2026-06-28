package dev.hg.grantmint.core.token;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The token header (segment A): {@code { "alg": "EdDSA", "typ": "GMT", "kid": ..., "crv": "Ed25519" }}.
 *
 * <p>The algorithm is <strong>pinned</strong> to {@code EdDSA} — verifiers reject anything else,
 * closing the classic JWT algorithm-confusion hole ({@code none}, {@code RS256}, …). {@code typ} is
 * {@code GMT} ("GrantMint Token"), distinguishing it from generic JWTs. {@code kid} here is the
 * <em>signing-key id</em> (which key pair signed), letting a verifier pick the matching embedded
 * public key after rotation. See docs/features/LICENSE_TOKEN_FORMAT.md.
 */
public record TokenHeader(String alg, String typ, String kid, String crv) {

    public static final String ALG_EDDSA = "EdDSA";
    public static final String TYP_GMT = "GMT";
    public static final String CRV_ED25519 = "Ed25519";

    public TokenHeader {
        Objects.requireNonNull(alg, "alg");
        Objects.requireNonNull(typ, "typ");
        Objects.requireNonNull(kid, "kid");
        Objects.requireNonNull(crv, "crv");
    }

    /** The canonical Grantmint header for a given signing-key id. */
    public static TokenHeader forSigningKey(String signingKeyId) {
        return new TokenHeader(ALG_EDDSA, TYP_GMT, signingKeyId, CRV_ED25519);
    }

    /** Whether this header declares the one allowed algorithm. */
    public boolean isAlgorithmAllowed() {
        return ALG_EDDSA.equals(alg);
    }

    /** The claim map serialized as segment A (keys are sorted by the canonical serializer). */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("alg", alg);
        map.put("typ", typ);
        map.put("kid", kid);
        map.put("crv", crv);
        return map;
    }

    /** Reconstruct a header from a parsed JSON map. */
    public static TokenHeader fromMap(Map<String, ?> map) {
        Objects.requireNonNull(map, "map");
        return new TokenHeader(asString(map, "alg"), asString(map, "typ"), asString(map, "kid"), asString(map, "crv"));
    }

    private static String asString(Map<String, ?> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof String s)) {
            throw new IllegalArgumentException("Header field '" + key + "' must be a string");
        }
        return s;
    }
}
