package dev.hg.grantmint.cli;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.time.Clock;
import dev.hg.grantmint.core.token.FailureReason;
import dev.hg.grantmint.core.token.LicenseVerifier;
import dev.hg.grantmint.core.token.TokenHeader;
import dev.hg.grantmint.core.token.TokenPayload;
import dev.hg.grantmint.core.token.VerificationResult;
import java.io.IOException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * {@code grantmint verify} — offline license-token verification against an embedded Ed25519 public
 * key. No network call is made; this is the client-side correctness boundary described in
 * docs/features/LICENSE_TOKEN_FORMAT.md.
 *
 * <p>Exit codes are scriptable per failure class (2026-07-05 audit, GRANTMINT-147 — every rejection
 * used to collapse to 1, so a script could not tell EXPIRED from FORGED without parsing stdout):
 * {@code 0} valid; {@code 1} untrustworthy credential (malformed, forged, wrong scheme or type);
 * {@code 2} usage error (unreadable token file, undecodable public key); {@code 3} expired; {@code
 * 4} not yet valid; {@code 5} wrong product; {@code 6} unsupported token format version. Nonzero
 * always means "do not accept"; codes ≥3 are authentic credentials refused for a stated reason.
 */
@Command(
        name = "verify",
        description = "Verify a license token offline against a public key. No network call.",
        footer = {
            "",
            "Exit codes:",
            "  0  valid",
            "  1  untrustworthy credential (malformed, forged, wrong scheme/type)",
            "  2  usage error",
            "  3  expired",
            "  4  not yet valid",
            "  5  wrong product (only with --product)",
            "  6  unsupported token format version"
        })
public final class VerifyCommand implements Callable<Integer> {

    @Option(
            names = {"--token"},
            required = true,
            description = "The signed token, or @path/to/file to read it from.")
    String tokenArg;

    @Option(
            names = {"--public-key"},
            required = true,
            description = "The Ed25519 public key, standard base64 (the raw 32-byte RFC 8032 encoding).")
    String publicKeyArg;

    @Option(
            names = {"--product"},
            description = "Expected product slug; the token's prd claim must equal it (exit 5 otherwise). "
                    + "Omit to skip product binding.")
    String productArg;

    @Override
    public Integer call() {
        String token;
        try {
            token = TokenInput.resolve(tokenArg);
        } catch (IOException e) {
            System.err.println("error: failed to read --token file: " + e.getMessage());
            return 2;
        }

        PublicKey publicKey;
        try {
            byte[] raw = Base64.getDecoder().decode(publicKeyArg.strip());
            publicKey = Ed25519Keys.decodePublicKey(raw);
        } catch (IllegalArgumentException e) {
            System.err.println("error: invalid --public-key: " + e.getMessage());
            return 2;
        }

        VerificationResult result = LicenseVerifier.verifyAt(token, publicKey, Clock.system(), productArg);
        if (!result.valid()) {
            System.out.println("INVALID: " + result.reason());
            return exitCodeFor(result.reason());
        }

        printClaims(result.header(), result.payload());
        return 0;
    }

    /**
     * The documented per-class exit codes (see the command footer). The untrustworthy reasons share
     * {@code 1} deliberately: which structural defect a forged token exhibits is not actionable for
     * a script, while expired / not-yet-valid / wrong-product / unsupported-version each are.
     */
    private static int exitCodeFor(FailureReason reason) {
        return switch (reason) {
            case MALFORMED, ALG_NOT_ALLOWED, WRONG_TYPE, FORGED -> 1;
            case EXPIRED -> 3;
            case NOT_YET_VALID -> 4;
            case WRONG_PRODUCT -> 5;
            case UNSUPPORTED_VERSION -> 6;
        };
    }

    private static void printClaims(TokenHeader header, TokenPayload payload) {
        System.out.println("VALID");
        System.out.println("  Signing key id: " + header.kid());
        System.out.println("  Key ID:         " + payload.kid());
        System.out.println("  Product:        " + payload.prd());
        System.out.println("  Policy:         " + payload.pol());
        System.out.println("  Holder:         " + payload.holder().name() + " <"
                + payload.holder().email() + ">");
        System.out.println("  Issued at:      " + Instant.ofEpochSecond(payload.iat()));
        System.out.println("  Expires:        "
                + (payload.exp() == null ? "never (perpetual)" : Instant.ofEpochSecond(payload.exp())));
        if (payload.seat() != null) {
            System.out.println("  Seats:          " + payload.seat());
        }
        System.out.println("  Entitlements:   " + formatEntitlements(payload));
    }

    private static String formatEntitlements(TokenPayload payload) {
        if (payload.entitlements().isEmpty()) {
            return "(none)";
        }
        return payload.entitlements().entitlements().stream()
                .map(e -> e.key() + "=" + e.value())
                .collect(Collectors.joining(", "));
    }
}
