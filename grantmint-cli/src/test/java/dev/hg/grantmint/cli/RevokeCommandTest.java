package dev.hg.grantmint.cli;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

/** Drives {@code grantmint revoke} against a lightweight {@link HttpServer} fake. */
class RevokeCommandTest {

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
    void revokesWithAReasonAndPrintsTheResult() throws Exception {
        AtomicReference<String> receivedMethod = new AtomicReference<>();
        AtomicReference<String> receivedAuth = new AtomicReference<>();
        AtomicReference<String> receivedPath = new AtomicReference<>();
        AtomicReference<String> receivedBody = new AtomicReference<>();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/issuance/licenses/", exchange -> {
            receivedMethod.set(exchange.getRequestMethod());
            receivedAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            receivedPath.set(exchange.getRequestURI().getPath());
            receivedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] response = ("{\"keyId\":\"7QF4-2K9M-XR1T\",\"status\":\"REVOKED\","
                            + "\"revokedAt\":\"2026-07-01T00:00:00Z\",\"reason\":\"customer requested\"}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        });
        server.start();
        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        int exitCode = new CommandLine(new GrantmintCli())
                .execute(
                        "revoke",
                        "--server",
                        baseUrl,
                        "--api-key",
                        "gm_live_test",
                        "--key-id",
                        "7QF4-2K9M-XR1T",
                        "--reason",
                        "customer requested");

        assertThat(exitCode).isZero();
        assertThat(receivedMethod.get()).isEqualTo("DELETE");
        assertThat(receivedAuth.get()).isEqualTo("Bearer gm_live_test");
        assertThat(receivedPath.get()).isEqualTo("/issuance/licenses/7QF4-2K9M-XR1T");
        assertThat(receivedBody.get()).contains("\"reason\":\"customer requested\"");
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("REVOKED").contains("customer requested");
    }

    @Test
    void nonTwoXxResponseExitsOne() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/issuance/licenses/", exchange -> {
            byte[] response =
                    "{\"error\":\"conflict\",\"message\":\"already revoked\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(409, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        });
        server.start();
        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        int exitCode = new CommandLine(new GrantmintCli())
                .execute("revoke", "--server", baseUrl, "--api-key", "gm_live_test", "--key-id", "7QF4-2K9M-XR1T");

        assertThat(exitCode).isEqualTo(1);
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("already revoked");
    }
}
