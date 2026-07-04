package dev.hg.grantmint.server.signing;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/**
 * Minimal HTTP seam for the secret-manager {@code private_key_ref} schemes ({@code vault:}, {@code
 * awssm:}, {@code gcpsm:}). Tests supply a lambda; production wraps the JDK {@link HttpClient}.
 * Deliberately tiny so no mocking framework is needed to exercise the resolvers.
 */
@FunctionalInterface
interface SecretHttp {

    Response send(String method, URI uri, Map<String, String> headers, byte[] body);

    record Response(int status, byte[] body) {
        String bodyUtf8() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    /** Production transport over the JDK client; created lazily so idle resolvers cost nothing. */
    static SecretHttp overJdk() {
        return new SecretHttp() {
            private volatile HttpClient client;

            @Override
            public Response send(String method, URI uri, Map<String, String> headers, byte[] body) {
                HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                        .timeout(Duration.ofSeconds(10))
                        .method(
                                method,
                                body == null
                                        ? HttpRequest.BodyPublishers.noBody()
                                        : HttpRequest.BodyPublishers.ofByteArray(body));
                headers.forEach(request::header);
                try {
                    HttpResponse<byte[]> response =
                            client().send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
                    return new Response(response.statusCode(), response.body());
                } catch (IOException e) {
                    throw new SigningKeyException("Secret-manager HTTP call to " + uri.getHost() + " failed", e);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new SigningKeyException("Secret-manager HTTP call to " + uri.getHost() + " interrupted", e);
                }
            }

            private HttpClient client() {
                HttpClient local = client;
                if (local == null) {
                    synchronized (this) {
                        if (client == null) {
                            client = HttpClient.newBuilder()
                                    .connectTimeout(Duration.ofSeconds(3))
                                    .followRedirects(HttpClient.Redirect.NEVER)
                                    .build();
                        }
                        local = client;
                    }
                }
                return local;
            }
        };
    }
}
