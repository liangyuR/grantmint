package dev.hg.grantmint.cli;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.entitlement.Entitlement;
import dev.hg.grantmint.core.entitlement.EntitlementSet;
import dev.hg.grantmint.core.token.Holder;
import dev.hg.grantmint.core.token.LicenseTokenIssuer;
import dev.hg.grantmint.core.token.TokenPayload;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

/**
 * Issues tokens with {@link LicenseTokenIssuer} exactly like {@code ValidationFlowIntegrationTest}
 * does server-side, then drives {@code grantmint verify} end to end through the {@link
 * GrantmintCli} entry point.
 */
class VerifyCommandTest {

    private final PrintStream originalOut = System.out;
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    @BeforeEach
    void redirectOut() {
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
    }

    @AfterEach
    void restoreOut() {
        System.setOut(originalOut);
    }

    @Test
    void validTokenExitsZeroAndPrintsClaims() {
        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());
        String publicKeyBase64 = publicKeyBase64Of(keyPair);
        String token = issue(
                keyPair, nowSeconds(), nowSeconds() + 3_600, EntitlementSet.of(Entitlement.flag("team_sync", true)));

        int exitCode = new CommandLine(new GrantmintCli())
                .execute("verify", "--token", token, "--public-key", publicKeyBase64);

        assertThat(exitCode).isZero();
        String printed = out.toString(StandardCharsets.UTF_8);
        assertThat(printed).contains("VALID");
        assertThat(printed).contains("7QF4-2K9M-XR1T");
        assertThat(printed).contains("team_sync=true");
    }

    @Test
    void expiredTokenExitsThree() {
        // Exit codes are per failure class (GRANTMINT-147): expired is 3, so a script can tell an
        // authentic-but-lapsed license apart from a forged one without parsing stdout.
        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());
        String publicKeyBase64 = publicKeyBase64Of(keyPair);
        long past = nowSeconds() - 10_000;
        String token = issue(keyPair, past, past + 10, EntitlementSet.empty());

        int exitCode = new CommandLine(new GrantmintCli())
                .execute("verify", "--token", token, "--public-key", publicKeyBase64);

        assertThat(exitCode).isEqualTo(3);
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("INVALID").contains("EXPIRED");
    }

    @Test
    void notYetValidTokenExitsFour() {
        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());
        String publicKeyBase64 = publicKeyBase64Of(keyPair);
        String token = issueWithNbf(keyPair, nowSeconds(), nowSeconds() + 5_000, nowSeconds() + 10_000);

        int exitCode = new CommandLine(new GrantmintCli())
                .execute("verify", "--token", token, "--public-key", publicKeyBase64);

        assertThat(exitCode).isEqualTo(4);
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("NOT_YET_VALID");
    }

    @Test
    void wrongProductExitsFiveAndOnlyWhenBindingIsRequested() {
        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());
        String publicKeyBase64 = publicKeyBase64Of(keyPair);
        String token = issue(keyPair, nowSeconds(), nowSeconds() + 3_600, EntitlementSet.empty());

        int bound = new CommandLine(new GrantmintCli())
                .execute("verify", "--token", token, "--public-key", publicKeyBase64, "--product", "other-app");
        assertThat(bound).isEqualTo(5);
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("WRONG_PRODUCT");

        int rightProduct = new CommandLine(new GrantmintCli())
                .execute("verify", "--token", token, "--public-key", publicKeyBase64, "--product", "acme-desktop");
        assertThat(rightProduct).isZero();
    }

    @Test
    void tamperedTokenExitsOne() {
        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());
        String publicKeyBase64 = publicKeyBase64Of(keyPair);
        String token = issue(keyPair, nowSeconds(), nowSeconds() + 3_600, EntitlementSet.empty());
        String[] parts = token.split("\\.", -1);
        String tampered = parts[0] + "." + parts[1] + "X" + "." + parts[2];

        int exitCode = new CommandLine(new GrantmintCli())
                .execute("verify", "--token", tampered, "--public-key", publicKeyBase64);

        assertThat(exitCode).isEqualTo(1);
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("INVALID");
    }

    @Test
    void malformedPublicKeyExitsTwo() {
        int exitCode = new CommandLine(new GrantmintCli())
                .execute("verify", "--token", "a.b.c", "--public-key", "not valid base64!!");

        assertThat(exitCode).isEqualTo(2);
    }

    @Test
    void tokenReadFromFileMatchesLiteralToken(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir)
            throws Exception {
        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());
        String publicKeyBase64 = publicKeyBase64Of(keyPair);
        String token = issue(keyPair, nowSeconds(), nowSeconds() + 3_600, EntitlementSet.empty());
        java.nio.file.Path tokenFile = dir.resolve("license.token");
        java.nio.file.Files.writeString(tokenFile, token + "\n");

        int exitCode = new CommandLine(new GrantmintCli())
                .execute("verify", "--token", "@" + tokenFile, "--public-key", publicKeyBase64);

        assertThat(exitCode).isZero();
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("VALID");
    }

    private static String publicKeyBase64Of(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(keyPair.getPublic()));
    }

    private static long nowSeconds() {
        return System.currentTimeMillis() / 1000;
    }

    private static String issue(KeyPair keyPair, long issuedAt, long expiresAt, EntitlementSet entitlements) {
        return issueWithNbf(keyPair, issuedAt, null, expiresAt, entitlements);
    }

    private static String issueWithNbf(KeyPair keyPair, long issuedAt, long notBefore, long expiresAt) {
        return issueWithNbf(keyPair, issuedAt, (Long) notBefore, expiresAt, EntitlementSet.empty());
    }

    private static String issueWithNbf(
            KeyPair keyPair, long issuedAt, Long notBefore, long expiresAt, EntitlementSet entitlements) {
        Ed25519Signer signer = new Ed25519Signer(keyPair.getPrivate(), "sk_test_1");
        LicenseTokenIssuer issuer = new LicenseTokenIssuer(signer);
        TokenPayload payload = new TokenPayload(
                TokenPayload.CURRENT_VERSION,
                UUID.randomUUID().toString(),
                "7QF4-2K9M-XR1T",
                "acme-desktop",
                "pro-annual",
                new Holder("Ada Lovelace", "ada@example.com"),
                issuedAt,
                notBefore,
                expiresAt,
                entitlements,
                null,
                2);
        return issuer.sign(payload);
    }
}
