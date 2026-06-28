package dev.hg.grantmint.core.token;

/**
 * Why offline verification rejected a token. Checks run in this order, and the first failure wins:
 *
 * <ol>
 *   <li>{@link #MALFORMED} — not three decodable base64url JSON segments;
 *   <li>{@link #ALG_NOT_ALLOWED} — the header does not pin the one allowed signature scheme,
 *       {@code alg=EdDSA} over {@code crv=Ed25519} (algorithm- or curve-confusion attempt);
 *   <li>{@link #FORGED} — the Ed25519 signature does not verify against the public key (tampered,
 *       forged, or signed by an unknown key);
 *   <li>{@link #NOT_YET_VALID} — {@code now} is before {@code nbf};
 *   <li>{@link #EXPIRED} — {@code now} is at or past {@code exp}.
 * </ol>
 *
 * <p>Signature authenticity is checked <em>before</em> the time claims so an attacker cannot learn
 * anything by editing {@code exp}/{@code nbf} on a forged token. See
 * docs/features/LICENSE_TOKEN_FORMAT.md.
 */
public enum FailureReason {
    MALFORMED,
    ALG_NOT_ALLOWED,
    FORGED,
    NOT_YET_VALID,
    EXPIRED
}
