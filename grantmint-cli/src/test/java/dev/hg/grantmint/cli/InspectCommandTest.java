package dev.hg.grantmint.cli;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.entitlement.EntitlementSet;
import dev.hg.grantmint.core.token.Holder;
import dev.hg.grantmint.core.token.LicenseTokenIssuer;
import dev.hg.grantmint.core.token.TokenPayload;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

class InspectCommandTest {

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
    void printsClaimsWithoutNeedingAKey() {
        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());
        Ed25519Signer signer = new Ed25519Signer(keyPair.getPrivate(), "sk_test_1");
        LicenseTokenIssuer issuer = new LicenseTokenIssuer(signer);
        long now = System.currentTimeMillis() / 1000;
        TokenPayload payload = new TokenPayload(
                TokenPayload.CURRENT_VERSION,
                UUID.randomUUID().toString(),
                "7QF4-2K9M-XR1T",
                "acme-desktop",
                "pro-annual",
                new Holder("Ada Lovelace", "ada@example.com"),
                now,
                null,
                now + 3_600,
                EntitlementSet.empty(),
                null,
                null);
        String token = issuer.sign(payload);

        int exitCode = new CommandLine(new GrantmintCli()).execute("inspect", "--token", token);

        assertThat(exitCode).isZero();
        String printed = out.toString(StandardCharsets.UTF_8);
        assertThat(printed).contains("UNVERIFIED");
        assertThat(printed).contains("7QF4-2K9M-XR1T");
        assertThat(printed).contains("acme-desktop");
        assertThat(printed).contains("sk_test_1");
    }

    @Test
    void malformedTokenExitsTwo() {
        int exitCode = new CommandLine(new GrantmintCli()).execute("inspect", "--token", "not-a-token");

        assertThat(exitCode).isEqualTo(2);
    }
}
