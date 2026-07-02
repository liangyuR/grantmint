package dev.hg.grantmint.cli;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

/** Drives {@code grantmint issue} against a lightweight {@link HttpServer} fake — no Spring context needed. */
class IssueCommandTest {

    private final PrintStream originalOut = System.out;
    private final PrintStream originalErr = System.err;
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();
    private HttpServer server;

    @BeforeEach
    void redirect() {
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    @AfterEach
    void restore() {
        System.setOut(originalOut);
        System.setErr(originalErr);
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void issuesAndPrintsTheResponse() throws Exception {
        AtomicReference<String> receivedAuth = new AtomicReference<>();
        AtomicReference<String> receivedBody = new AtomicReference<>();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/issuance/licenses", exchange -> {
            receivedAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            receivedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] response = ("{\"keyId\":\"7QF4-2K9M-XR1T\",\"token\":\"gmt1.aaa.bbb\",\"status\":\"ACTIVE\","
                            + "\"expiresAt\":\"2027-06-28T00:00:00Z\"}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(201, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        });
        server.start();
        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        int exitCode = new CommandLine(new GrantmintCli())
                .execute(
                        "issue",
                        "--server",
                        baseUrl,
                        "--api-key",
                        "gm_live_test",
                        "--policy-id",
                        UUID.randomUUID().toString(),
                        "--holder-name",
                        "Ada Lovelace",
                        "--holder-email",
                        "ada@example.com");

        assertThat(exitCode).isZero();
        assertThat(receivedAuth.get()).isEqualTo("Bearer gm_live_test");
        assertThat(receivedBody.get()).contains("\"name\":\"Ada Lovelace\"").contains("\"email\":\"ada@example.com\"");
        String printed = out.toString(StandardCharsets.UTF_8);
        assertThat(printed).contains("7QF4-2K9M-XR1T").contains("gmt1.aaa.bbb").contains("ACTIVE");
    }

    @Test
    void nonTwoXxResponseExitsOneAndPrintsTheErrorBody() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/issuance/licenses", exchange -> {
            byte[] response =
                    "{\"error\":\"not_found\",\"message\":\"no such policy\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(404, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        });
        server.start();
        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        int exitCode = new CommandLine(new GrantmintCli())
                .execute(
                        "issue",
                        "--server",
                        baseUrl,
                        "--api-key",
                        "gm_live_test",
                        "--policy-id",
                        UUID.randomUUID().toString(),
                        "--holder-name",
                        "Ada Lovelace",
                        "--holder-email",
                        "ada@example.com");

        assertThat(exitCode).isEqualTo(1);
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("no such policy");
    }

    @Test
    void invalidPolicyIdExitsTwoWithoutAnyRequest() {
        int exitCode = new CommandLine(new GrantmintCli())
                .execute(
                        "issue",
                        "--server",
                        "http://127.0.0.1:1",
                        "--api-key",
                        "gm_live_test",
                        "--policy-id",
                        "not-a-uuid",
                        "--holder-name",
                        "Ada Lovelace",
                        "--holder-email",
                        "ada@example.com");

        assertThat(exitCode).isEqualTo(2);
    }
}
