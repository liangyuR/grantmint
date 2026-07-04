package dev.hg.grantmint.server.signing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.Map;
import java.util.function.UnaryOperator;

/**
 * {@code gcpsm:projects/<p>/secrets/<s>[/versions/<v>]} (or the {@code <project>/<secret>[/<version>]}
 * shorthand) — read a secret version from GCP Secret Manager via the REST {@code :access} call,
 * SDK-free. The version defaults to {@code latest}; the payload bytes are the seed material (raw 32
 * bytes, hex, or base64).
 *
 * <p>Auth follows the Application-Default-Credentials order this build supports: a service-account
 * JSON at {@code GOOGLE_APPLICATION_CREDENTIALS} (RS256 JWT-bearer exchange at the account's {@code
 * token_uri}), else the GCE/GKE/Cloud Run metadata server.
 */
final class GcpSecretManagerSource {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String METADATA_TOKEN_URI =
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
    private static final String DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";
    private static final String SCOPE = "https://www.googleapis.com/auth/cloud-platform";

    private final SecretHttp http;
    private final UnaryOperator<String> environment;
    private final Clock clock;

    GcpSecretManagerSource(SecretHttp http, UnaryOperator<String> environment, Clock clock) {
        this.http = http;
        this.environment = environment;
        this.clock = clock;
    }

    byte[] fetch(String locator) {
        String resource = canonicalResource(locator);
        URI uri = URI.create("https://secretmanager.googleapis.com/v1/" + resource + ":access");
        SecretHttp.Response response = http.send("GET", uri, Map.of("Authorization", "Bearer " + accessToken()), null);
        if (response.status() != 200) {
            throw new SigningKeyException("GCP Secret Manager returned HTTP " + response.status()
                    + " for the private_key_ref secret (check the resource name and IAM binding)");
        }
        try {
            JsonNode data = JSON.readTree(response.body()).path("payload").path("data");
            if (!data.isTextual()) {
                throw new SigningKeyException("GCP Secret Manager response carried no payload data");
            }
            return Base64.getDecoder().decode(data.asText());
        } catch (java.io.IOException e) {
            throw new SigningKeyException("GCP Secret Manager response was not valid JSON", e);
        }
    }

    /** Accepts the full resource name or {@code <project>/<secret>[/<version>]}; defaults to latest. */
    static String canonicalResource(String locator) {
        String trimmed = locator.startsWith("/") ? locator.substring(1) : locator;
        if (trimmed.isBlank()) {
            throw new SigningKeyException("gcpsm: ref is missing the secret resource name");
        }
        if (trimmed.startsWith("projects/")) {
            return trimmed.contains("/versions/") ? trimmed : trimmed + "/versions/latest";
        }
        String[] parts = trimmed.split("/");
        if (parts.length < 2 || parts.length > 3) {
            throw new SigningKeyException("gcpsm: ref must be 'projects/<p>/secrets/<s>[/versions/<v>]'"
                    + " or '<project>/<secret>[/<version>]'");
        }
        String version = parts.length == 3 ? parts[2] : "latest";
        return "projects/" + parts[0] + "/secrets/" + parts[1] + "/versions/" + version;
    }

    private String accessToken() {
        String credentialsPath = environment.apply("GOOGLE_APPLICATION_CREDENTIALS");
        if (credentialsPath != null && !credentialsPath.isBlank()) {
            return serviceAccountToken(credentialsPath);
        }
        SecretHttp.Response response =
                http.send("GET", URI.create(METADATA_TOKEN_URI), Map.of("Metadata-Flavor", "Google"), null);
        if (response.status() != 200) {
            throw new SigningKeyException("No GCP credentials: set GOOGLE_APPLICATION_CREDENTIALS or run on GCP"
                    + " (metadata server token request failed)");
        }
        return tokenFrom(response);
    }

    private String serviceAccountToken(String credentialsPath) {
        JsonNode account;
        try {
            account = JSON.readTree(Files.readAllBytes(Path.of(credentialsPath)));
        } catch (java.io.IOException e) {
            throw new SigningKeyException("Failed to read GOOGLE_APPLICATION_CREDENTIALS file", e);
        }
        String clientEmail = account.path("client_email").asText(null);
        String privateKeyPem = account.path("private_key").asText(null);
        if (clientEmail == null || privateKeyPem == null) {
            throw new SigningKeyException(
                    "GOOGLE_APPLICATION_CREDENTIALS file is missing client_email/private_key (need a service-account"
                            + " key, not a user credential)");
        }
        String tokenUri = account.path("token_uri").asText(DEFAULT_TOKEN_URI);

        long now = clock.instant().getEpochSecond();
        String header = base64Url("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String claims = base64Url(("{\"iss\":\"" + clientEmail + "\",\"scope\":\"" + SCOPE + "\",\"aud\":\"" + tokenUri
                        + "\",\"iat\":" + now + ",\"exp\":" + (now + 3600) + "}")
                .getBytes(StandardCharsets.UTF_8));
        String assertion = header + "." + claims + "." + base64Url(rs256(privateKeyPem, header + "." + claims));

        byte[] form = ("grant_type=" + AwsSigV4.rfc3986Encode("urn:ietf:params:oauth:grant-type:jwt-bearer")
                        + "&assertion=" + assertion)
                .getBytes(StandardCharsets.UTF_8);
        SecretHttp.Response response = http.send(
                "POST", URI.create(tokenUri), Map.of("content-type", "application/x-www-form-urlencoded"), form);
        if (response.status() != 200) {
            throw new SigningKeyException("GCP token exchange returned HTTP " + response.status()
                    + " (check the service-account key and its clock/expiry)");
        }
        return tokenFrom(response);
    }

    private static String tokenFrom(SecretHttp.Response response) {
        try {
            String token = JSON.readTree(response.body()).path("access_token").asText(null);
            if (token == null || token.isBlank()) {
                throw new SigningKeyException("GCP token response carried no access_token");
            }
            return token;
        } catch (java.io.IOException e) {
            throw new SigningKeyException("GCP token response was not valid JSON", e);
        }
    }

    private static byte[] rs256(String privateKeyPem, String signingInput) {
        try {
            String base64 = privateKeyPem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            PrivateKey key = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key);
            signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return signature.sign();
        } catch (java.security.GeneralSecurityException | IllegalArgumentException e) {
            throw new SigningKeyException(
                    "GOOGLE_APPLICATION_CREDENTIALS private_key is not a valid RSA PKCS#8 key", e);
        }
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
