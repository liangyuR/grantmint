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
 *       may be null (perpetual) — absence is malformed; {@code lid}/{@code kid}/{@code prd}/
 *       {@code pol}/{@code hld} (with string {@code n}/{@code e}) and {@code iat} are required per
 *       the spec's claim table; {@code nbf} is genuinely optional;
 *   <li>product binding (when an expected product is given) <em>before</em> the temporal window —
 *       the reference checks {@code prd} ahead of {@code nbf}/{@code exp}, so an expired token for
 *       the wrong product is WRONG_PRODUCT in both implementations, never EXPIRED in one of them;
 *   <li>{@code now >= exp} is expired (exp exclusive), {@code now < nbf} not yet valid.
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

    /** Verify at the configured clock's now, with no product binding. */
    public VerifiedToken verify(String token) {
        return verifyAt(token, null, clock.instant());
    }

    /** Verify at the configured clock's now, bound to {@code expectedProduct} (null skips binding). */
    public VerifiedToken verify(String token, String expectedProduct) {
        return verifyAt(token, expectedProduct, clock.instant());
    }

    /** Verify the token as of {@code now}, with no product binding. */
    public VerifiedToken verifyAt(String token, Instant now) {
        return verifyAt(token, null, now);
    }

    /**
     * Verify the token as of {@code now}. When {@code expectedProduct} is non-null, the
     * authenticated {@code prd} claim must equal it — checked between the format-version gate and
     * the temporal window, mirroring the reference verifier's step order so both implementations
     * report the same reason for the same bytes.
     *
     * @throws TokenVerificationException when the token is malformed, forged, for another product,
     *     expired, or not yet valid — the reason says which
     */
    public VerifiedToken verifyAt(String token, String expectedProduct, Instant now) {
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
        return checkClaims(parsePayload(segments[1]), expectedProduct, now);
    }

    private static void pinHeader(byte[] headerBytes) {
        Map<String, Object> header;
        try {
            header = StrictJson.parseObject(new String(headerBytes, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException bad) {
            throw malformed("header is not strict JSON");
        }
        // Same order and granularity as the reference verifier: header structure first (all four
        // fields present as strings — a kid-less header is MALFORMED, exactly like the reference's
        // decodeHeader), then the signature-scheme pin, then the token-type pin, each with its own
        // reason — all before any signature work.
        for (String field : new String[] {"alg", "typ", "kid", "crv"}) {
            if (!(header.get(field) instanceof String)) {
                throw malformed("header field '" + field + "' must be a string");
            }
        }
        if (!"EdDSA".equals(header.get("alg")) || !"Ed25519".equals(header.get("crv"))) {
            throw new TokenVerificationException(
                    Reason.ALG_NOT_ALLOWED, "header is not pinned to alg=EdDSA, crv=Ed25519");
        }
        if (!"GMT".equals(header.get("typ"))) {
            throw new TokenVerificationException(Reason.WRONG_TYPE, "header typ is not GMT");
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

    private static VerifiedToken checkClaims(Map<String, Object> claims, String expectedProduct, Instant now) {
        // exp is REQUIRED on the wire; its value may be null (perpetual). Absence is malformed —
        // never silently perpetual (CROSS_VERIFIER_FIXTURES.md, perpetual licenses note).
        if (!claims.containsKey("exp")) {
            throw malformed("exp claim is required (null means perpetual, absent is invalid)");
        }
        Long exp = optionalEpoch(claims, "exp");
        Long nbf = optionalEpoch(claims, "nbf");
        // The spec's claim table marks lid/kid/prd/pol/hld/iat required non-empty and ent a required
        // object (LICENSE_TOKEN_FORMAT.md); mirror the reference verifier exactly: absence, a wrong
        // type, or an empty required string is MALFORMED, never a silently-defaulted field — and,
        // like the reference, every structural check runs before the version gate and the temporal
        // window so both implementations report the same reason for the same bytes.
        long iat = requiredEpoch(claims, "iat");
        String kid = requiredString(claims, "kid");
        String lid = requiredString(claims, "lid");
        String prd = requiredString(claims, "prd");
        String pol = requiredString(claims, "pol");
        Map<String, Object> holder = requiredObject(claims, "hld");
        String holderName = requiredString(holder, "n");
        String holderEmail = requiredString(holder, "e");
        Map<String, Object> entitlements = requiredObject(claims, "ent");
        // The reference's EntitlementSet.decode admits exactly flag | limit | string values under
        // canonical snake_case keys (^[a-z][a-z0-9_]{0,62}$ — the grammar the server enforces at
        // entitlement creation); anything else in a signed ent is malformed there and so must be
        // here. Rejecting non-canonical keys (rather than normalizing) keeps two JSON-distinct
        // keys like "MAX_DEVICES"/"max_devices" from collapsing last-wins in one SDK while staying
        // distinct in another.
        for (Map.Entry<String, Object> entitlement : entitlements.entrySet()) {
            if (!isCanonicalEntitlementKey(entitlement.getKey())) {
                throw malformed("entitlement keys must be canonical snake_case");
            }
            Object value = entitlement.getValue();
            if (!(value instanceof Boolean || value instanceof Long || value instanceof String)) {
                throw malformed("entitlement values must be a boolean flag, integer limit, or string");
            }
        }
        Integer seat = optionalInt(claims, "seat");
        Map<String, Object> constraints = optionalObject(claims, "con");

        // Format-version gate — the structure is sound, but refuse to interpret a layout this
        // verifier does not understand. A non-integer or out-of-int-range ver is malformed like any
        // other claim (the reference parses ver as an int); a well-typed unknown version gets its
        // own reason.
        if (!(claims.get("ver") instanceof Long version)
                || version < Integer.MIN_VALUE
                || version > Integer.MAX_VALUE) {
            throw malformed("ver must be an integer format version");
        }
        if (version != 1L) {
            throw new TokenVerificationException(
                    Reason.UNSUPPORTED_VERSION, "unsupported token version " + version, kid);
        }

        // Product binding before the temporal window — the reference's step order (an authentic
        // token for a sibling product must not pass another product's gate, and the reason must not
        // depend on whether it also happens to be expired).
        if (expectedProduct != null && !expectedProduct.equals(prd)) {
            throw new TokenVerificationException(
                    Reason.WRONG_PRODUCT, "token is for product '" + prd + "', not '" + expectedProduct + "'", kid);
        }

        if (nbf != null && now.getEpochSecond() < nbf) {
            throw new TokenVerificationException(Reason.NOT_YET_VALID, "token not valid before " + nbf, kid);
        }
        if (exp != null && now.getEpochSecond() >= exp) {
            throw new TokenVerificationException(Reason.EXPIRED, "token expired at " + exp, kid);
        }

        return new VerifiedToken(
                kid,
                lid,
                prd,
                pol,
                holderName,
                holderEmail,
                Instant.ofEpochSecond(iat),
                nbf == null ? null : Instant.ofEpochSecond(nbf),
                exp == null ? null : Instant.ofEpochSecond(exp),
                entitlements,
                seat,
                constraints);
    }

    /**
     * An optional int-domain claim: the spec types {@code seat} as a plain int (not an epoch
     * second), and the reference parses it with {@code Math.toIntExact} — so a value outside the
     * 32-bit range is malformed here exactly as it is there, never silently widened. Same rationale
     * as the {@code ver} gate above.
     */
    private static Integer optionalInt(Map<String, Object> claims, String key) {
        Long value = optionalEpoch(claims, key);
        if (value == null) {
            return null;
        }
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
            throw malformed(key + " must fit a 32-bit integer");
        }
        return value.intValue();
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

    private static long requiredEpoch(Map<String, Object> claims, String key) {
        if (!(claims.get(key) instanceof Long epoch)) {
            throw malformed("missing required integer claim: " + key);
        }
        return epoch;
    }

    /**
     * The reference's {@code EntitlementKey.isCanonical}: {@code ^[a-z][a-z0-9_]{0,62}$}. A pure
     * ASCII character-class check — byte-deterministic across the Java, Swift, Go, and TS verifiers,
     * with no Unicode case-folding parity risk.
     */
    private static boolean isCanonicalEntitlementKey(String key) {
        int length = key.length();
        if (length < 1 || length > 63) {
            return false;
        }
        char first = key.charAt(0);
        if (first < 'a' || first > 'z') {
            return false;
        }
        for (int i = 1; i < length; i++) {
            char c = key.charAt(i);
            boolean lower = c >= 'a' && c <= 'z';
            boolean digit = c >= '0' && c <= '9';
            if (!lower && !digit && c != '_') {
                return false;
            }
        }
        return true;
    }

    private static String requiredString(Map<String, Object> claims, String key) {
        if (!(claims.get(key) instanceof String value) || value.isEmpty()) {
            throw malformed("missing required claim: " + key);
        }
        return value;
    }

    private static Map<String, Object> requiredObject(Map<String, Object> claims, String key) {
        Map<String, Object> value = optionalObject(claims, key);
        if (value == null) {
            throw malformed("missing required claim: " + key);
        }
        return value;
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
