package dev.hg.grantmint.server.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

/**
 * The {@code awssm:} scheme: SigV4-signed GetSecretValue request shape, SecretString/SecretBinary
 * and JSON-field extraction, ARN region parsing, and the env → ECS → IMDSv2 credential chain.
 */
class AwsSecretsManagerSourceTest {

    private static final CommandRunner NO_EXEC = argv -> {
        throw new AssertionError("unexpected exec");
    };
    private static final Clock FIXED = Clock.fixed(Instant.parse("2026-01-15T10:30:00Z"), ZoneOffset.UTC);

    private final byte[] seed = Ed25519Keys.encodePrivateKey(
            Ed25519Keys.generate(new SecureRandom()).getPrivate());
    private final String seedHex = HexFormat.of().formatHex(seed);

    private final UnaryOperator<String> envCreds = name -> Map.of(
                    "AWS_REGION", "eu-central-1",
                    "AWS_ACCESS_KEY_ID", "AKIDUNITTEST",
                    "AWS_SECRET_ACCESS_KEY", "unit-test-secret", // gitleaks:allow — fake test credential
                    "AWS_SESSION_TOKEN", "unit-test-session")
            .get(name);

    @Test
    void signsGetSecretValueAndResolvesSecretString() {
        AtomicReference<URI> requestedUri = new AtomicReference<>();
        AtomicReference<Map<String, String>> sentHeaders = new AtomicReference<>();
        AtomicReference<String> sentBody = new AtomicReference<>();
        SecretHttp http = (method, uri, headers, body) -> {
            assertThat(method).isEqualTo("POST");
            requestedUri.set(uri);
            sentHeaders.set(headers);
            sentBody.set(new String(body, StandardCharsets.UTF_8));
            return new SecretHttp.Response(
                    200, ("{\"SecretString\":\"" + seedHex + "\"}").getBytes(StandardCharsets.UTF_8));
        };
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(envCreds, http, NO_EXEC, FIXED);

        assertThat(resolver.resolveSeed("awssm:grantmint/signing-seed")).containsExactly(seed);
        assertThat(requestedUri.get()).hasHost("secretsmanager.eu-central-1.amazonaws.com");
        assertThat(sentBody.get()).isEqualTo("{\"SecretId\":\"grantmint/signing-seed\"}");
        assertThat(sentHeaders.get())
                .containsEntry("x-amz-target", "secretsmanager.GetSecretValue")
                .containsEntry("x-amz-date", "20260115T103000Z")
                .containsEntry("x-amz-security-token", "unit-test-session");
        assertThat(sentHeaders.get().get("authorization"))
                .startsWith("AWS4-HMAC-SHA256 Credential=AKIDUNITTEST/20260115/eu-central-1/secretsmanager/"
                        + "aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target,"
                        + " Signature=");
    }

    @Test
    void extractsJsonFieldFromSecretString() {
        SecretHttp http = (method, uri, headers, body) -> new SecretHttp.Response(
                200,
                ("{\"SecretString\":\"{\\\"seed\\\":\\\"" + seedHex + "\\\",\\\"other\\\":\\\"x\\\"}\"}")
                        .getBytes(StandardCharsets.UTF_8));
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(envCreds, http, NO_EXEC, FIXED);
        assertThat(resolver.resolveSeed("awssm:grantmint/signing-seed#seed")).containsExactly(seed);
    }

    @Test
    void decodesSecretBinary() {
        String binary = Base64.getEncoder().encodeToString(seed);
        SecretHttp http = (method, uri, headers, body) -> new SecretHttp.Response(
                200, ("{\"SecretBinary\":\"" + binary + "\"}").getBytes(StandardCharsets.UTF_8));
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(envCreds, http, NO_EXEC, FIXED);
        assertThat(resolver.resolveSeed("awssm:grantmint/signing-seed")).containsExactly(seed);
    }

    @Test
    void takesRegionFromArnOverEnv() {
        AtomicReference<URI> requestedUri = new AtomicReference<>();
        SecretHttp http = (method, uri, headers, body) -> {
            requestedUri.set(uri);
            return new SecretHttp.Response(
                    200, ("{\"SecretString\":\"" + seedHex + "\"}").getBytes(StandardCharsets.UTF_8));
        };
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(envCreds, http, NO_EXEC, FIXED);
        resolver.resolveSeed("awssm:arn:aws:secretsmanager:us-west-2:123456789012:secret:grantmint-abc");
        assertThat(requestedUri.get()).hasHost("secretsmanager.us-west-2.amazonaws.com");
    }

    @Test
    void fallsBackToEcsContainerCredentials() {
        UnaryOperator<String> env = name -> Map.of(
                        "AWS_REGION", "eu-central-1",
                        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/uuid")
                .get(name);
        SecretHttp http = (method, uri, headers, body) -> {
            if ("169.254.170.2".equals(uri.getHost())) {
                assertThat(uri.getPath()).isEqualTo("/v2/credentials/uuid");
                return new SecretHttp.Response(
                        200,
                        ("{\"AccessKeyId\":\"AKIDECS\",\"SecretAccessKey\":\"ecs-secret\",\"Token\":\"ecs-token\"}")
                                .getBytes(StandardCharsets.UTF_8));
            }
            assertThat(headers.get("authorization")).contains("Credential=AKIDECS/");
            assertThat(headers).containsEntry("x-amz-security-token", "ecs-token");
            return new SecretHttp.Response(
                    200, ("{\"SecretString\":\"" + seedHex + "\"}").getBytes(StandardCharsets.UTF_8));
        };
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(env, http, NO_EXEC, FIXED);
        assertThat(resolver.resolveSeed("awssm:grantmint/signing-seed")).containsExactly(seed);
    }

    @Test
    void fallsBackToImdsV2() {
        UnaryOperator<String> env = name -> "AWS_REGION".equals(name) ? "eu-central-1" : null;
        SecretHttp http = (method, uri, headers, body) -> {
            if ("169.254.169.254".equals(uri.getHost())) {
                if ("PUT".equals(method)) {
                    return new SecretHttp.Response(200, "imds-token".getBytes(StandardCharsets.UTF_8));
                }
                assertThat(headers).containsEntry("x-aws-ec2-metadata-token", "imds-token");
                if (uri.getPath().endsWith("/security-credentials/")) {
                    return new SecretHttp.Response(200, "grantmint-role\n".getBytes(StandardCharsets.UTF_8));
                }
                assertThat(uri.getPath()).endsWith("/security-credentials/grantmint-role");
                return new SecretHttp.Response(
                        200,
                        ("{\"AccessKeyId\":\"AKIDIMDS\",\"SecretAccessKey\":\"imds-secret\",\"Token\":\"imds-tok\"}")
                                .getBytes(StandardCharsets.UTF_8));
            }
            assertThat(headers.get("authorization")).contains("Credential=AKIDIMDS/");
            return new SecretHttp.Response(
                    200, ("{\"SecretString\":\"" + seedHex + "\"}").getBytes(StandardCharsets.UTF_8));
        };
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(env, http, NO_EXEC, FIXED);
        assertThat(resolver.resolveSeed("awssm:grantmint/signing-seed")).containsExactly(seed);
    }

    @Test
    void requiresRegionWhenLocatorIsNotAnArn() {
        UnaryOperator<String> env = name -> null;
        SecretHttp http = (method, uri, headers, body) -> {
            throw new AssertionError("must not call AWS without a region");
        };
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(env, http, NO_EXEC, FIXED);
        assertThatThrownBy(() -> resolver.resolveSeed("awssm:grantmint/signing-seed"))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("AWS_REGION");
    }

    @Test
    void surfacesNonOkStatusWithoutBody() {
        SecretHttp http = (method, uri, headers, body) -> new SecretHttp.Response(
                400, "{\"__type\":\"ResourceNotFoundException\"}".getBytes(StandardCharsets.UTF_8));
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(envCreds, http, NO_EXEC, FIXED);
        assertThatThrownBy(() -> resolver.resolveSeed("awssm:missing"))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("HTTP 400");
    }
}
