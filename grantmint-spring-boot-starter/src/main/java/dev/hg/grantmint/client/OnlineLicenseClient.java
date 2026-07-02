package dev.hg.grantmint.client;

import dev.hg.grantmint.client.verify.StrictJsonAccess;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Map;

/**
 * The optional online layer — validate / activate / deactivate / heartbeat against a Grantmint
 * server with the Scheme-3 validation key. Built on {@code java.net.http} so the starter carries no
 * HTTP-client dependency. Network failures never throw out of {@link #validate}: they surface as
 * {@link LicenseStatus.Reason#SERVER_UNREACHABLE} so the validator can apply the configured
 * fail-open/fail-closed policy. See docs/features/CLIENT_SDK.md and docs/api/API_DOCUMENTATION.md.
 */
public class OnlineLicenseClient {

    private static final String VALIDATION_HEADER = "X-Grantmint-Validation";

    private final HttpClient http;
    private final String baseUrl;
    private final String validationKey;
    private final java.time.Duration readTimeout;

    public OnlineLicenseClient(GrantmintClientProperties props) {
        this(
                HttpClient.newBuilder()
                        .connectTimeout(props.getOnline().getConnectTimeout())
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build(),
                props);
    }

    OnlineLicenseClient(HttpClient http, GrantmintClientProperties props) {
        if (props.getServerUrl() == null || props.getServerUrl().isBlank()) {
            throw new IllegalArgumentException("grantmint.client.server-url is required for online/hybrid mode");
        }
        this.http = http;
        this.baseUrl = props.getServerUrl().replaceAll("/+$", "");
        this.validationKey = props.getValidationKey();
        this.readTimeout = props.getOnline().getReadTimeout();
    }

    /** Online validation: database truth — revocation, suspension, activation state. */
    public LicenseStatus validate(String keyId, String fingerprint) {
        HttpResponse<String> response;
        try {
            response = post("/v1/licenses/validate", body(keyId, fingerprint));
        } catch (IOException | InterruptedException unreachable) {
            restoreInterrupt(unreachable);
            return LicenseStatus.invalid(LicenseStatus.Reason.SERVER_UNREACHABLE, keyId);
        }
        return switch (response.statusCode()) {
            case 200 -> parseValid(keyId, response.body());
            case 404, 422 -> LicenseStatus.invalid(reasonOf(errorCode(response.body())), keyId);
            default -> LicenseStatus.invalid(LicenseStatus.Reason.SERVER_UNREACHABLE, keyId);
        };
    }

    /** Claim a seat for this device. Idempotent per fingerprint — safe to call on every launch. */
    public LicenseStatus activate(String keyId, String fingerprint) {
        return seatCall("/v1/licenses/activate", keyId, fingerprint);
    }

    /** Release this device's seat. */
    public LicenseStatus deactivate(String keyId, String fingerprint) {
        return seatCall("/v1/licenses/deactivate", keyId, fingerprint);
    }

    /** Keep the seat alive; also how a device learns of revocation between validations. */
    public LicenseStatus heartbeat(String keyId, String fingerprint) {
        return seatCall("/v1/licenses/heartbeat", keyId, fingerprint);
    }

    private LicenseStatus seatCall(String path, String keyId, String fingerprint) {
        HttpResponse<String> response;
        try {
            response = post(path, body(keyId, fingerprint));
        } catch (IOException | InterruptedException unreachable) {
            restoreInterrupt(unreachable);
            return LicenseStatus.invalid(LicenseStatus.Reason.SERVER_UNREACHABLE, keyId);
        }
        int code = response.statusCode();
        if (code == 200 || code == 201) {
            return new LicenseStatus(true, LicenseStatus.Reason.VALID, keyId, null, null, Map.of(), false);
        }
        return LicenseStatus.invalid(reasonOf(errorCode(response.body())), keyId);
    }

    private HttpResponse<String> post(String path, String jsonBody) throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(readTimeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));
        if (validationKey != null && !validationKey.isBlank()) {
            request.header(VALIDATION_HEADER, validationKey);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static String body(String keyId, String fingerprint) {
        StringBuilder sb =
                new StringBuilder("{\"keyId\":\"").append(escape(keyId)).append('"');
        if (fingerprint != null && !fingerprint.isBlank()) {
            sb.append(",\"fingerprint\":\"").append(escape(fingerprint)).append('"');
        }
        return sb.append('}').toString();
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private LicenseStatus parseValid(String keyId, String body) {
        Map<String, Object> json = StrictJsonAccess.parseObjectLenient(body);
        if (json == null || !Boolean.TRUE.equals(json.get("valid"))) {
            return LicenseStatus.invalid(LicenseStatus.Reason.SERVER_UNREACHABLE, keyId);
        }
        Instant expiresAt = null;
        if (json.get("expiresAt") instanceof String iso) {
            try {
                expiresAt = OffsetDateTime.parse(iso).toInstant();
            } catch (RuntimeException ignored) {
                // A malformed timestamp does not invalidate an otherwise-valid answer.
            }
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> entitlements =
                json.get("entitlements") instanceof Map ? (Map<String, Object>) json.get("entitlements") : Map.of();
        return new LicenseStatus(true, LicenseStatus.Reason.VALID, keyId, null, expiresAt, entitlements, false);
    }

    private static String errorCode(String body) {
        Map<String, Object> json = StrictJsonAccess.parseObjectLenient(body);
        return json != null && json.get("error") instanceof String code ? code : "";
    }

    /** Map the server's stable reason codes onto the client's vocabulary. */
    private static LicenseStatus.Reason reasonOf(String code) {
        return switch (code) {
            case "license_revoked" -> LicenseStatus.Reason.REVOKED;
            case "license_suspended" -> LicenseStatus.Reason.SUSPENDED;
            case "license_expired" -> LicenseStatus.Reason.EXPIRED;
            case "license_not_yet_valid" -> LicenseStatus.Reason.NOT_YET_VALID;
            case "license_inactive" -> LicenseStatus.Reason.INACTIVE;
            case "seat_limit_exceeded" -> LicenseStatus.Reason.SEAT_LIMIT_EXCEEDED;
            default -> LicenseStatus.Reason.INVALID_SIGNATURE;
        };
    }

    private static void restoreInterrupt(Exception e) {
        if (e instanceof InterruptedException) {
            Thread.currentThread().interrupt();
        }
    }
}
