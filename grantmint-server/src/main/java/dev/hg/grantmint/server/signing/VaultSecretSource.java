package dev.hg.grantmint.server.signing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.function.UnaryOperator;

/**
 * {@code vault:<api-path>[#<field>]} — read a secret from HashiCorp Vault over its HTTP API.
 *
 * <p>The locator is the API path under {@code /v1/} — for a KV v2 engine that includes the {@code
 * data/} segment (e.g. {@code vault:secret/data/grantmint/signing#seed}); plain KV v1 / logical
 * paths work as written. Both KV v1 ({@code data.<field>}) and KV v2 ({@code data.data.<field>})
 * response shapes are understood. The fragment names the field holding the seed; it may be omitted
 * when the secret has exactly one field.
 *
 * <p>Configuration comes from the standard Vault environment: {@code VAULT_ADDR} (required), {@code
 * VAULT_TOKEN} (required), {@code VAULT_NAMESPACE} (optional, Vault Enterprise).
 */
final class VaultSecretSource {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final SecretHttp http;
    private final UnaryOperator<String> environment;

    VaultSecretSource(SecretHttp http, UnaryOperator<String> environment) {
        this.http = http;
        this.environment = environment;
    }

    byte[] fetch(String locator) {
        String path = locator;
        String field = null;
        int hash = locator.lastIndexOf('#');
        if (hash >= 0) {
            path = locator.substring(0, hash);
            field = locator.substring(hash + 1);
        }
        if (path.isBlank()) {
            throw new SigningKeyException("vault: ref is missing the secret path");
        }
        String address = requireEnv("VAULT_ADDR");
        String token = requireEnv("VAULT_TOKEN");

        Map<String, String> headers = new java.util.LinkedHashMap<>();
        headers.put("X-Vault-Token", token);
        String namespace = environment.apply("VAULT_NAMESPACE");
        if (namespace != null && !namespace.isBlank()) {
            headers.put("X-Vault-Namespace", namespace);
        }
        URI uri = URI.create(stripTrailingSlash(address) + "/v1/" + stripLeadingSlash(path));
        SecretHttp.Response response = http.send("GET", uri, headers, null);
        if (response.status() != 200) {
            throw new SigningKeyException("Vault returned HTTP " + response.status() + " for the private_key_ref path"
                    + " (check VAULT_ADDR/VAULT_TOKEN and the policy on '" + path + "')");
        }
        return selectField(parse(response), field).getBytes(StandardCharsets.UTF_8);
    }

    private static JsonNode parse(SecretHttp.Response response) {
        try {
            JsonNode root = JSON.readTree(response.body());
            JsonNode data = root.path("data");
            // KV v2 nests the secret under data.data; KV v1 puts it directly under data.
            return data.path("data").isObject() ? data.path("data") : data;
        } catch (java.io.IOException e) {
            throw new SigningKeyException("Vault response was not valid JSON", e);
        }
    }

    private static String selectField(JsonNode data, String field) {
        if (!data.isObject() || data.isEmpty()) {
            throw new SigningKeyException("Vault secret has no data fields at the private_key_ref path");
        }
        if (field != null) {
            JsonNode value = data.path(field);
            if (!value.isTextual()) {
                throw new SigningKeyException(
                        "Vault secret field '" + field + "' is missing or not a string; check the '#<field>' fragment");
            }
            return value.asText();
        }
        if (data.size() != 1) {
            throw new SigningKeyException(
                    "Vault secret has multiple fields; append '#<field>' to the private_key_ref to pick one");
        }
        JsonNode only = data.elements().next();
        if (!only.isTextual()) {
            throw new SigningKeyException("Vault secret field is not a string");
        }
        return only.asText();
    }

    private String requireEnv(String name) {
        String value = environment.apply(name);
        if (value == null || value.isBlank()) {
            throw new SigningKeyException(name + " must be set to resolve a vault: private_key_ref");
        }
        return value;
    }

    private static String stripTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    private static String stripLeadingSlash(String s) {
        return s.startsWith("/") ? s.substring(1) : s;
    }
}
