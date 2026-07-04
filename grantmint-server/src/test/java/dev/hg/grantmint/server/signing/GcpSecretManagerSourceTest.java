package dev.hg.grantmint.server.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The {@code gcpsm:} scheme: resource-name canonicalization, the metadata-server token path, and the
 * service-account JWT-bearer path (the RS256 assertion is verified against the account's public key).
 */
class GcpSecretManagerSourceTest {

    private static final CommandRunner NO_EXEC = argv -> {
        throw new AssertionError("unexpected exec");
    };
    private static final Clock FIXED = Clock.fixed(Instant.parse("2026-01-15T10:30:00Z"), ZoneOffset.UTC);

    private final byte[] seed = Ed25519Keys.encodePrivateKey(
            Ed25519Keys.generate(new SecureRandom()).getPrivate());
    private final String payloadB64 = Base64.getEncoder().encodeToString(seed);

    @Test
    void canonicalizesResourceNames() {
        assertThat(GcpSecretManagerSource.canonicalResource("my-proj/signing-seed"))
                .isEqualTo("projects/my-proj/secrets/signing-seed/versions/latest");
        assertThat(GcpSecretManagerSource.canonicalResource("my-proj/signing-seed/7"))
                .isEqualTo("projects/my-proj/secrets/signing-seed/versions/7");
        assertThat(GcpSecretManagerSource.canonicalResource("projects/p/secrets/s"))
                .isEqualTo("projects/p/secrets/s/versions/latest");
        assertThat(GcpSecretManagerSource.canonicalResource("projects/p/secrets/s/versions/3"))
                .isEqualTo("projects/p/secrets/s/versions/3");
        assertThatThrownBy(() -> GcpSecretManagerSource.canonicalResource("just-one-segment"))
                .isInstanceOf(SigningKeyException.class);
    }

    @Test
    void resolvesViaMetadataServerToken() {
        SecretHttp http = (method, uri, headers, body) -> {
            if ("metadata.google.internal".equals(uri.getHost())) {
                assertThat(headers).containsEntry("Metadata-Flavor", "Google");
                return new SecretHttp.Response(
                        200, "{\"access_token\":\"metadata-token\"}".getBytes(StandardCharsets.UTF_8));
            }
            assertThat(uri.toString())
                    .isEqualTo("https://secretmanager.googleapis.com/v1/projects/my-proj/secrets/signing-seed"
                            + "/versions/latest:access");
            assertThat(headers).containsEntry("Authorization", "Bearer metadata-token");
            return new SecretHttp.Response(
                    200, ("{\"payload\":{\"data\":\"" + payloadB64 + "\"}}").getBytes(StandardCharsets.UTF_8));
        };
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(name -> null, http, NO_EXEC, FIXED);
        assertThat(resolver.resolveSeed("gcpsm:my-proj/signing-seed")).containsExactly(seed);
    }

    @Test
    void resolvesViaServiceAccountJwtBearer(@TempDir Path dir) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair rsa = generator.generateKeyPair();
        Path saFile = writeServiceAccountJson(dir, rsa);
        UnaryOperator<String> env = name -> "GOOGLE_APPLICATION_CREDENTIALS".equals(name) ? saFile.toString() : null;

        SecretHttp http = (method, uri, headers, body) -> {
            if ("oauth2.googleapis.com".equals(uri.getHost())) {
                String form = new String(body, StandardCharsets.UTF_8);
                assertThat(form).contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer");
                String assertion =
                        URLDecoder.decode(form.substring(form.indexOf("&assertion=") + 11), StandardCharsets.UTF_8);
                verifyRs256(assertion, rsa);
                String claims =
                        new String(Base64.getUrlDecoder().decode(assertion.split("\\.")[1]), StandardCharsets.UTF_8);
                assertThat(claims).contains("\"iss\":\"unit@test.iam.gserviceaccount.com\"");
                return new SecretHttp.Response(200, "{\"access_token\":\"sa-token\"}".getBytes(StandardCharsets.UTF_8));
            }
            assertThat(headers).containsEntry("Authorization", "Bearer sa-token");
            return new SecretHttp.Response(
                    200, ("{\"payload\":{\"data\":\"" + payloadB64 + "\"}}").getBytes(StandardCharsets.UTF_8));
        };
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(env, http, NO_EXEC, FIXED);
        assertThat(resolver.resolveSeed("gcpsm:projects/p/secrets/s")).containsExactly(seed);
    }

    @Test
    void surfacesFailedTokenExchange(@TempDir Path dir) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        Path saFile = writeServiceAccountJson(dir, generator.generateKeyPair());
        UnaryOperator<String> env = name -> "GOOGLE_APPLICATION_CREDENTIALS".equals(name) ? saFile.toString() : null;
        SecretHttp http =
                (method, uri, headers, body) -> new SecretHttp.Response(401, "{}".getBytes(StandardCharsets.UTF_8));
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(env, http, NO_EXEC, FIXED);
        assertThatThrownBy(() -> resolver.resolveSeed("gcpsm:projects/p/secrets/s"))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("token exchange returned HTTP 401");
    }

    private static Path writeServiceAccountJson(Path dir, KeyPair rsa) throws IOException {
        String pem = "-----BEGIN PRIVATE KEY-----\n" // gitleaks:allow — throwaway key generated per test run
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                        .encodeToString(rsa.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        Path file = dir.resolve("sa.json");
        Files.writeString(
                file,
                "{\"type\":\"service_account\",\"client_email\":\"unit@test.iam.gserviceaccount.com\","
                        + "\"private_key\":" + quote(pem)
                        + ",\"token_uri\":\"https://oauth2.googleapis.com/token\"}",
                StandardCharsets.UTF_8);
        return file;
    }

    private static void verifyRs256(String jwt, KeyPair rsa) {
        try {
            String[] parts = jwt.split("\\.");
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(rsa.getPublic());
            verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
            assertThat(verifier.verify(Base64.getUrlDecoder().decode(parts[2])))
                    .as("assertion must be RS256-signed by the service-account key")
                    .isTrue();
        } catch (java.security.GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\n", "\\n").replace("\"", "\\\"") + "\"";
    }
}
