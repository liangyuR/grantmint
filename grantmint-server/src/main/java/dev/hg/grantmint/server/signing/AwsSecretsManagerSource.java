package dev.hg.grantmint.server.signing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.UnaryOperator;

/**
 * {@code awssm:<secret-id-or-arn>[#<json-field>]} — read a secret from AWS Secrets Manager via a
 * SigV4-signed {@code GetSecretValue}, SDK-free.
 *
 * <p>The region comes from the ARN when the locator is one, else from {@code AWS_REGION} / {@code
 * AWS_DEFAULT_REGION}. Credentials resolve through the standard chain subset: static environment
 * variables ({@code AWS_ACCESS_KEY_ID}/{@code AWS_SECRET_ACCESS_KEY}[/{@code AWS_SESSION_TOKEN}]),
 * then the ECS/EKS container credentials endpoint ({@code AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}),
 * then EC2 IMDSv2. Without a fragment the whole {@code SecretString} (or raw {@code SecretBinary})
 * is the seed material; with one, {@code SecretString} is parsed as JSON and the named field used.
 */
final class AwsSecretsManagerSource {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final DateTimeFormatter AMZ_DATE =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final String ECS_CREDENTIALS_HOST = "http://169.254.170.2";
    private static final String IMDS_HOST = "http://169.254.169.254";

    private final SecretHttp http;
    private final UnaryOperator<String> environment;
    private final Clock clock;

    AwsSecretsManagerSource(SecretHttp http, UnaryOperator<String> environment, Clock clock) {
        this.http = http;
        this.environment = environment;
        this.clock = clock;
    }

    byte[] fetch(String locator) {
        String secretId = locator;
        String field = null;
        int hash = locator.lastIndexOf('#');
        if (hash >= 0) {
            secretId = locator.substring(0, hash);
            field = locator.substring(hash + 1);
        }
        if (secretId.isBlank()) {
            throw new SigningKeyException("awssm: ref is missing the secret id/ARN");
        }
        String region = resolveRegion(secretId);
        Credentials credentials = resolveCredentials();

        URI uri = URI.create("https://secretsmanager." + region + ".amazonaws.com/");
        byte[] body = ("{\"SecretId\":" + quoteJson(secretId) + "}").getBytes(StandardCharsets.UTF_8);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("content-type", "application/x-amz-json-1.1");
        headers.put("x-amz-target", "secretsmanager.GetSecretValue");
        headers.put("x-amz-date", AMZ_DATE.format(clock.instant()));
        if (credentials.sessionToken() != null) {
            headers.put("x-amz-security-token", credentials.sessionToken());
        }
        headers.put(
                "authorization",
                AwsSigV4.authorizationHeader(
                        "POST",
                        uri,
                        withoutAuthorization(headers),
                        body,
                        region,
                        "secretsmanager",
                        credentials.accessKeyId(),
                        credentials.secretAccessKey(),
                        headers.get("x-amz-date")));

        SecretHttp.Response response = http.send("POST", uri, headers, body);
        if (response.status() != 200) {
            throw new SigningKeyException("AWS Secrets Manager returned HTTP " + response.status()
                    + " for the private_key_ref secret (check the secret id, region, and IAM policy)");
        }
        return extractMaterial(response, field);
    }

    private static Map<String, String> withoutAuthorization(Map<String, String> headers) {
        Map<String, String> signed = new LinkedHashMap<>(headers);
        signed.remove("authorization");
        return signed;
    }

    private static byte[] extractMaterial(SecretHttp.Response response, String field) {
        JsonNode root;
        try {
            root = JSON.readTree(response.body());
        } catch (java.io.IOException e) {
            throw new SigningKeyException("AWS Secrets Manager response was not valid JSON", e);
        }
        JsonNode secretString = root.path("SecretString");
        if (secretString.isTextual()) {
            if (field == null) {
                return secretString.asText().getBytes(StandardCharsets.UTF_8);
            }
            try {
                JsonNode value = JSON.readTree(secretString.asText()).path(field);
                if (!value.isTextual()) {
                    throw new SigningKeyException("AWS secret JSON field '" + field
                            + "' is missing or not a string; check the '#<field>' fragment");
                }
                return value.asText().getBytes(StandardCharsets.UTF_8);
            } catch (java.io.IOException e) {
                throw new SigningKeyException(
                        "AWS SecretString is not JSON but the private_key_ref names a '#<field>'", e);
            }
        }
        JsonNode secretBinary = root.path("SecretBinary");
        if (secretBinary.isTextual()) {
            if (field != null) {
                throw new SigningKeyException("AWS secret is binary; drop the '#<field>' fragment");
            }
            return Base64.getDecoder().decode(secretBinary.asText());
        }
        throw new SigningKeyException("AWS Secrets Manager response carried neither SecretString nor SecretBinary");
    }

    private String resolveRegion(String secretId) {
        if (secretId.startsWith("arn:")) {
            String[] parts = secretId.split(":");
            if (parts.length > 3 && !parts[3].isBlank()) {
                return parts[3];
            }
        }
        String region = firstNonBlank(environment.apply("AWS_REGION"), environment.apply("AWS_DEFAULT_REGION"));
        if (region == null) {
            throw new SigningKeyException("Set AWS_REGION (or use a full ARN) to resolve an awssm: private_key_ref");
        }
        return region;
    }

    record Credentials(String accessKeyId, String secretAccessKey, String sessionToken) {}

    /** Static env vars → ECS container endpoint → EC2 IMDSv2, in that order. */
    Credentials resolveCredentials() {
        String accessKeyId = environment.apply("AWS_ACCESS_KEY_ID");
        String secretAccessKey = environment.apply("AWS_SECRET_ACCESS_KEY");
        if (accessKeyId != null && !accessKeyId.isBlank() && secretAccessKey != null && !secretAccessKey.isBlank()) {
            return new Credentials(accessKeyId, secretAccessKey, blankToNull(environment.apply("AWS_SESSION_TOKEN")));
        }
        String containerUri = environment.apply("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
        if (containerUri != null && !containerUri.isBlank()) {
            return parseCredentials(http.send("GET", URI.create(ECS_CREDENTIALS_HOST + containerUri), Map.of(), null));
        }
        return imdsCredentials();
    }

    private Credentials imdsCredentials() {
        SecretHttp.Response tokenResponse = http.send(
                "PUT",
                URI.create(IMDS_HOST + "/latest/api/token"),
                Map.of("x-aws-ec2-metadata-token-ttl-seconds", "300"),
                null);
        if (tokenResponse.status() != 200) {
            throw new SigningKeyException("No AWS credentials: set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, run with"
                    + " an ECS task role, or run on EC2 with an instance profile (IMDSv2 token request failed)");
        }
        Map<String, String> imdsToken =
                Map.of("x-aws-ec2-metadata-token", tokenResponse.bodyUtf8().strip());
        SecretHttp.Response roleResponse = http.send(
                "GET", URI.create(IMDS_HOST + "/latest/meta-data/iam/security-credentials/"), imdsToken, null);
        if (roleResponse.status() != 200 || roleResponse.bodyUtf8().isBlank()) {
            throw new SigningKeyException("EC2 instance has no IAM role attached (IMDS security-credentials empty)");
        }
        String role = roleResponse.bodyUtf8().strip().lines().findFirst().orElseThrow();
        return parseCredentials(http.send(
                "GET", URI.create(IMDS_HOST + "/latest/meta-data/iam/security-credentials/" + role), imdsToken, null));
    }

    private static Credentials parseCredentials(SecretHttp.Response response) {
        if (response.status() != 200) {
            throw new SigningKeyException("AWS credentials endpoint returned HTTP " + response.status());
        }
        try {
            JsonNode root = JSON.readTree(response.body());
            String accessKeyId = root.path("AccessKeyId").asText(null);
            String secretAccessKey = root.path("SecretAccessKey").asText(null);
            if (accessKeyId == null || secretAccessKey == null) {
                throw new SigningKeyException("AWS credentials endpoint response is missing key material fields");
            }
            return new Credentials(
                    accessKeyId, secretAccessKey, blankToNull(root.path("Token").asText(null)));
        } catch (java.io.IOException e) {
            throw new SigningKeyException("AWS credentials endpoint response was not valid JSON", e);
        }
    }

    private static String quoteJson(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        return (b != null && !b.isBlank()) ? b : null;
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value;
    }
}
