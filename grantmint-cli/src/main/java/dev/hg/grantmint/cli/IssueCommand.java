package dev.hg.grantmint.cli;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * {@code grantmint issue} — mint a license via the server's issuance API: {@code POST
 * /issuance/licenses}, authenticated with a per-product issuance API key (Scheme 2: {@code
 * Authorization: Bearer gm_live_...}/{@code gm_test_...}). See {@code
 * dev.hg.grantmint.server.api.IssuanceController} for the exact request/response shape this command
 * speaks.
 *
 * <p>Exit codes: {@code 0} issued, {@code 1} the server rejected the request or was unreachable,
 * {@code 2} usage error (malformed {@code --policy-id}).
 */
@Command(name = "issue", description = "Issue a new license from a running Grantmint server.")
public final class IssueCommand implements Callable<Integer> {

    @Option(
            names = {"--server"},
            required = true,
            description = "Base URL of the Grantmint server, e.g. http://localhost:8080")
    String server;

    @Option(
            names = {"--api-key"},
            required = true,
            description = "Issuance API key (gm_live_... / gm_test_...).")
    String apiKey;

    @Option(
            names = {"--policy-id"},
            required = true,
            description = "UUID of the policy to issue from.")
    String policyIdArg;

    @Option(
            names = {"--holder-name"},
            required = true,
            description = "The licensee's name.")
    String holderName;

    @Option(
            names = {"--holder-email"},
            required = true,
            description = "The licensee's email.")
    String holderEmail;

    @Option(
            names = {"--expires-at"},
            description = "ISO-8601 expiry timestamp, overriding the policy's default duration.")
    String expiresAt;

    @Option(
            names = {"--seats"},
            description = "Seat count, overriding the policy's default.")
    Integer seats;

    @Override
    public Integer call() {
        UUID policyId;
        try {
            policyId = UUID.fromString(policyIdArg);
        } catch (IllegalArgumentException e) {
            System.err.println("error: --policy-id is not a valid UUID: " + policyIdArg);
            return 2;
        }

        Map<String, Object> holder = new LinkedHashMap<>();
        holder.put("name", holderName);
        holder.put("email", holderEmail);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("policyId", policyId.toString());
        body.put("holder", holder);
        if (expiresAt != null) {
            body.put("expiresAt", expiresAt);
        }
        if (seats != null) {
            body.put("seat", seats);
        }

        URI uri = URI.create(CliHttp.stripTrailingSlash(server) + "/issuance/licenses");
        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(30))
                .POST(BodyPublishers.ofString(JsonBody.serialize(body)))
                .build();

        HttpResponse<String> response;
        try {
            response = HttpClient.newHttpClient().send(request, BodyHandlers.ofString());
        } catch (IOException e) {
            System.err.println("error: request to " + uri + " failed: " + e.getMessage());
            return 1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("error: request to " + uri + " was interrupted");
            return 1;
        }

        if (response.statusCode() / 100 != 2) {
            CliHttp.printServerError(response);
            return 1;
        }

        Object json = JsonBody.parseOrNull(response.body());
        System.out.println("Issued license:");
        System.out.println("  Key ID:     " + JsonBody.stringField(json, "keyId"));
        System.out.println("  Status:     " + JsonBody.stringField(json, "status"));
        System.out.println("  Expires at: " + JsonBody.stringField(json, "expiresAt"));
        System.out.println("  Token:      " + JsonBody.stringField(json, "token"));
        return 0;
    }
}
