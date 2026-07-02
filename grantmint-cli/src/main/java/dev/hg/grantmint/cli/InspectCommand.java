package dev.hg.grantmint.cli;

import dev.hg.grantmint.core.token.MalformedTokenException;
import dev.hg.grantmint.core.token.SignedToken;
import dev.hg.grantmint.core.token.TokenCodec;
import dev.hg.grantmint.core.token.TokenHeader;
import dev.hg.grantmint.core.token.TokenPayload;
import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * {@code grantmint inspect} — decode and print a token's header and claims WITHOUT verifying the
 * signature. Purely a debugging aid: an unverified token could be forged, expired, or belong to
 * another product, so its claims must never drive an authorization decision. Use {@code grantmint
 * verify} for that.
 *
 * <p>Exit codes: {@code 0} decoded successfully, {@code 2} the input is not a well-formed token (or
 * {@code --token} file could not be read).
 */
@Command(name = "inspect", description = "Decode a token's claims WITHOUT verifying its signature.")
public final class InspectCommand implements Callable<Integer> {

    @Option(
            names = {"--token"},
            required = true,
            description = "The signed token, or @path/to/file to read it from.")
    String tokenArg;

    @Override
    public Integer call() {
        String token;
        try {
            token = TokenInput.resolve(tokenArg);
        } catch (IOException e) {
            System.err.println("error: failed to read --token file: " + e.getMessage());
            return 2;
        }

        TokenHeader header;
        TokenPayload payload;
        try {
            SignedToken parts = SignedToken.parse(token);
            header = TokenCodec.decodeHeader(parts.headerSegment());
            payload = TokenCodec.decodePayload(parts.payloadSegment());
        } catch (MalformedTokenException e) {
            System.err.println("error: not a well-formed token: " + e.getMessage());
            return 2;
        }

        System.out.println("*** UNVERIFIED — signature NOT checked. Never trust these claims for an "
                + "authorization decision; use `grantmint verify` instead. ***");
        System.out.println();
        System.out.println("Header:");
        System.out.println("  alg: " + header.alg());
        System.out.println("  typ: " + header.typ());
        System.out.println("  kid: " + header.kid());
        System.out.println("  crv: " + header.crv());
        System.out.println();
        System.out.println("Payload:");
        System.out.println("  ver:  " + payload.ver());
        System.out.println("  lid:  " + payload.lid());
        System.out.println("  kid:  " + payload.kid());
        System.out.println("  prd:  " + payload.prd());
        System.out.println("  pol:  " + payload.pol());
        System.out.println(
                "  hld:  " + payload.holder().name() + " <" + payload.holder().email() + ">");
        System.out.println("  iat:  " + payload.iat() + " (" + Instant.ofEpochSecond(payload.iat()) + ")");
        if (payload.nbf() != null) {
            System.out.println("  nbf:  " + payload.nbf() + " (" + Instant.ofEpochSecond(payload.nbf()) + ")");
        }
        System.out.println("  exp:  "
                + (payload.exp() == null
                        ? "null (perpetual)"
                        : payload.exp() + " (" + Instant.ofEpochSecond(payload.exp()) + ")"));
        System.out.println("  ent:  " + formatEntitlements(payload));
        if (payload.seat() != null) {
            System.out.println("  seat: " + payload.seat());
        }
        if (payload.constraints() != null && !payload.constraints().isEmpty()) {
            System.out.println("  con:  " + formatConstraints(payload.constraints()));
        }
        return 0;
    }

    private static String formatEntitlements(TokenPayload payload) {
        if (payload.entitlements().isEmpty()) {
            return "(none)";
        }
        return payload.entitlements().entitlements().stream()
                .map(e -> e.key() + "=" + e.value())
                .collect(Collectors.joining(", "));
    }

    private static String formatConstraints(Map<String, Object> constraints) {
        return constraints.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining(", "));
    }
}
