package dev.hg.grantmint.server.webhook;

import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * The raw webhook request as received — headers plus the UNMODIFIED body bytes. Signatures are
 * computed over exact bytes, so the body must never pass through a parse/re-serialize cycle before
 * verification. Header names are looked up case-insensitively (HTTP header names are
 * case-insensitive; servlet containers disagree on the casing they report).
 */
public record WebhookRequest(byte[] rawBody, Map<String, String> headers) {

    public WebhookRequest {
        TreeMap<String, String> normalized = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        normalized.putAll(headers);
        headers = normalized;
    }

    /** The header value, matched case-insensitively; empty string when absent. */
    public String header(String name) {
        return headers.getOrDefault(name.toLowerCase(Locale.ROOT), "");
    }
}
