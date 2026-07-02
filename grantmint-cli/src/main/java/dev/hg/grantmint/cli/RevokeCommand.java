package dev.hg.grantmint.cli;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * {@code grantmint revoke} — terminally revoke a license: {@code DELETE
 * /issuance/licenses/{keyId}}, authenticated the same way as {@code issue}. There is no un-revoke;
 * see {@code dev.hg.grantmint.server.api.LicenseLifecycleController}.
 *
 * <p>Exit codes: {@code 0} revoked, {@code 1} the server rejected the request (e.g. already revoked,
 * unknown key id) or was unreachable.
 */
@Command(name = "revoke", description = "Revoke a license (terminal — cannot be undone).")
public final class RevokeCommand implements Callable<Integer> {

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
            names = {"--key-id"},
            required = true,
            description = "The license key ID to revoke, e.g. 7QF4-2K9M-XR1T.")
    String keyId;

    @Option(
            names = {"--reason"},
            description = "Optional reason, recorded on the license and in the audit trail.")
    String reason;

    @Override
    public Integer call() {
        BodyPublisher body;
        if (reason != null) {
            Map<String, Object> fields = new LinkedHashMap<>();
            fields.put("reason", reason);
            body = BodyPublishers.ofString(JsonBody.serialize(fields));
        } else {
            body = BodyPublishers.noBody();
        }

        URI uri = URI.create(CliHttp.stripTrailingSlash(server) + "/issuance/licenses/" + keyId.strip());
        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(30))
                .method("DELETE", body)
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
        System.out.println("Revoked: " + JsonBody.stringField(json, "keyId"));
        System.out.println("  Status:     " + JsonBody.stringField(json, "status"));
        System.out.println("  Revoked at: " + JsonBody.stringField(json, "revokedAt"));
        String returnedReason = JsonBody.stringField(json, "reason");
        if (returnedReason != null) {
            System.out.println("  Reason:     " + returnedReason);
        }
        return 0;
    }
}
