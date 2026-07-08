package dev.hg.grantmint.core.token;

/**
 * Why offline verification rejected a token. Checks run in this order, and the first failure wins:
 *
 * <ol>
 *   <li>{@link #MALFORMED} — not three strictly-decodable base64url segments carrying well-formed
 *       header/payload JSON. All three segments are decoded eagerly, before any other gate, in
 *       every verifier (core, starter, Go, Swift, TS) — so a corrupt segment is MALFORMED
 *       everywhere, never a downstream reason like {@code FORGED} or {@code ALG_NOT_ALLOWED};
 *   <li>{@link #ALG_NOT_ALLOWED} — the header does not pin the one allowed signature scheme,
 *       {@code alg=EdDSA} over {@code crv=Ed25519} (algorithm- or curve-confusion attempt);
 *   <li>{@link #WRONG_TYPE} — the header {@code typ} is not {@code GMT}; this is not a Grantmint
 *       token (e.g. a generic JWT presented to the verifier);
 *   <li>{@link #FORGED} — the Ed25519 signature does not verify against the public key (tampered,
 *       forged, or signed by an unknown key);
 *   <li>{@link #UNSUPPORTED_VERSION} — the (now-authenticated) payload {@code ver} is not a format
 *       version this verifier understands; refusing to interpret an unknown layout is fail-closed;
 *   <li>{@link #WRONG_PRODUCT} — the (now-authenticated) payload {@code prd} is not the product the
 *       caller expected; an authentic token for product A presented to product B's gate. Only
 *       reported when the caller supplies an expected product id (the offline SDK guard against a
 *       multi-product, single-key-pair deployment accepting a sibling product's token);
 *   <li>{@link #NOT_YET_VALID} — {@code now} is before {@code nbf};
 *   <li>{@link #EXPIRED} — {@code now} is at or past {@code exp}.
 * </ol>
 *
 * <p>Header gates ({@code ALG_NOT_ALLOWED}, {@code WRONG_TYPE}) run before the signature; signature
 * authenticity is checked <em>before</em> the version, product, and time claims so an attacker cannot
 * learn anything by editing {@code ver}/{@code prd}/{@code exp}/{@code nbf} on a forged token. See
 * docs/features/LICENSE_TOKEN_FORMAT.md.
 */
public enum FailureReason {
    MALFORMED,
    ALG_NOT_ALLOWED,
    WRONG_TYPE,
    FORGED,
    UNSUPPORTED_VERSION,
    WRONG_PRODUCT,
    NOT_YET_VALID,
    EXPIRED
}
