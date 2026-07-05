package dev.hg.grantmint.client.verify;

import java.time.Instant;
import java.util.Map;

/**
 * The claims of a token whose signature, header pinning, and temporal window all checked out.
 * Everything here was read from the signed bytes — never from any preview or re-serialized copy.
 *
 * @param keyId the short online license key id ({@code kid} claim), e.g. {@code K7P2-9QXM-4T1A}
 * @param licenseId the server's license id ({@code lid})
 * @param product the product key the license belongs to ({@code prd})
 * @param policy the policy key it was minted from ({@code pol})
 * @param holderName licensee display name ({@code hld.n}, may be null)
 * @param holderEmail licensee email ({@code hld.e}, may be null)
 * @param issuedAt {@code iat}
 * @param notBefore {@code nbf}, null when the token is valid immediately
 * @param expiresAt {@code exp}; null means perpetual — the claim was present with a null value
 * @param entitlements the decoded {@code ent} claim (flags, limits, strings)
 * @param seatLimit the {@code seat} claim — an int on the wire, like the reference's model
 * @param constraints the free-form {@code con} claim
 */
public record VerifiedToken(
        String keyId,
        String licenseId,
        String product,
        String policy,
        String holderName,
        String holderEmail,
        Instant issuedAt,
        Instant notBefore,
        Instant expiresAt,
        Map<String, Object> entitlements,
        Integer seatLimit,
        Map<String, Object> constraints) {

    public VerifiedToken {
        entitlements = entitlements == null ? Map.of() : Map.copyOf(entitlements);
        constraints = constraints == null ? Map.of() : Map.copyOf(constraints);
    }
}
