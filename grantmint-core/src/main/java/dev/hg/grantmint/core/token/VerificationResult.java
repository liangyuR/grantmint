package dev.hg.grantmint.core.token;

import java.util.Objects;
import java.util.Optional;

/**
 * The outcome of offline verification: either valid with the verified header + claims, or invalid
 * with a {@link FailureReason}.
 *
 * <p>Verification returns a result rather than throwing for expected rejections (forged, expired,
 * not-yet-valid, malformed). This keeps the security-critical path branch-free and makes it trivial
 * to property-test thousands of tampered tokens without exception overhead. Claims are present only
 * when {@link #valid()} is {@code true} — never read entitlements from an invalid result.
 */
public record VerificationResult(boolean valid, FailureReason reason, TokenHeader header, TokenPayload payload) {

    /** A successful verification carrying the authenticated header and claims. */
    public static VerificationResult ok(TokenHeader header, TokenPayload payload) {
        return new VerificationResult(true, null, Objects.requireNonNull(header), Objects.requireNonNull(payload));
    }

    /** A failed verification with the reason it was rejected. */
    public static VerificationResult failure(FailureReason reason) {
        return new VerificationResult(false, Objects.requireNonNull(reason), null, null);
    }

    /** Convenience alias for {@link #valid()}. */
    public boolean isValid() {
        return valid;
    }

    /** The verified claims, present only on success. */
    public Optional<TokenPayload> payloadIfValid() {
        return Optional.ofNullable(payload);
    }
}
