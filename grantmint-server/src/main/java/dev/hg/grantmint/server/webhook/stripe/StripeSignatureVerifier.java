package dev.hg.grantmint.server.webhook.stripe;

import dev.hg.grantmint.server.webhook.WebhookRequest;
import dev.hg.grantmint.server.webhook.WebhookSignatureException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Verifies Stripe's {@code Stripe-Signature: t=&lt;unix-ts&gt;,v1=&lt;hex-hmac&gt;} header — the
 * security heart of webhook ingestion, since the signature is that surface's only authentication.
 * Three non-negotiables (docs/features/WEBHOOK_INTEGRATION.md):
 *
 * <ol>
 *   <li>The HMAC is computed over {@code "<t>." + raw body bytes} — never a parsed-then-reserialized
 *       object, whose byte layout would differ and break the MAC.
 *   <li>Comparison is constant-time ({@link MessageDigest#isEqual}) to avoid timing leaks.
 *   <li>The timestamp must sit inside the tolerance window, so a captured webhook cannot be
 *       replayed later.
 * </ol>
 *
 * <p>Multiple {@code v1} signatures are accepted if <em>any</em> matches — Stripe sends several
 * during signing-secret rotation. The clock is injected (never {@code Instant.now()}) so the replay
 * window is testable deterministically. This HMAC is unrelated to the Ed25519 license token: it
 * proves <em>the provider sent this request</em>, not that Grantmint minted anything.
 */
final class StripeSignatureVerifier {

    private final byte[] signingSecret;
    private final Duration tolerance;
    private final Clock clock;

    StripeSignatureVerifier(String signingSecret, Duration tolerance, Clock clock) {
        if (signingSecret == null || signingSecret.isBlank()) {
            throw new IllegalArgumentException("stripe signing secret must be configured");
        }
        this.signingSecret = signingSecret.getBytes(StandardCharsets.UTF_8);
        this.tolerance = tolerance;
        this.clock = clock;
    }

    void verify(WebhookRequest request) throws WebhookSignatureException {
        // An absent header is safe here: WebhookRequest.header() returns "" (never null) for a
        // missing name, which falls through to the malformed-header rejection below — pinned by
        // aMissingSignatureHeaderIsRejectedNotAnNpe.
        String header = request.header("stripe-signature");
        long timestamp = 0;
        List<String> candidates = new ArrayList<>();
        for (String part : header.split(",")) {
            String[] kv = part.split("=", 2);
            if (kv.length != 2) {
                continue;
            }
            switch (kv[0].trim()) {
                case "t" -> timestamp = parseTimestamp(kv[1].trim());
                case "v1" -> candidates.add(kv[1].trim());
                default -> {
                    // Unknown scheme versions (v0, future vN) are ignored, per Stripe's contract.
                }
            }
        }
        if (timestamp <= 0 || candidates.isEmpty()) {
            throw new WebhookSignatureException("malformed Stripe-Signature header");
        }

        // Replay defense: a signature is only proof-of-origin within the tolerance window.
        long skew = Math.abs(clock.instant().getEpochSecond() - timestamp);
        if (skew > tolerance.toSeconds()) {
            throw new WebhookSignatureException("timestamp outside tolerance");
        }

        byte[] computed = hexHmacSha256(signedPayload(timestamp, request.rawBody()));
        boolean anyMatch = false;
        for (String candidate : candidates) {
            // Constant-time compare; evaluate every candidate so match position leaks nothing.
            anyMatch |= MessageDigest.isEqual(computed, candidate.getBytes(StandardCharsets.UTF_8));
        }
        if (!anyMatch) {
            throw new WebhookSignatureException("signature mismatch");
        }
    }

    private static long parseTimestamp(String raw) throws WebhookSignatureException {
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException malformed) {
            throw new WebhookSignatureException("malformed Stripe-Signature timestamp");
        }
    }

    /** {@code "<t>." + raw body} — the exact bytes Stripe signed. */
    private static byte[] signedPayload(long timestamp, byte[] body) {
        byte[] prefix = (timestamp + ".").getBytes(StandardCharsets.UTF_8);
        byte[] signed = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, signed, 0, prefix.length);
        System.arraycopy(body, 0, signed, prefix.length, body.length);
        return signed;
    }

    /** Lowercase-hex HMAC-SHA256 as bytes, matching the header's encoding for the comparison. */
    private byte[] hexHmacSha256(byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(signingSecret, "HmacSHA256"));
            byte[] out = mac.doFinal(message);
            StringBuilder sb = new StringBuilder(out.length * 2);
            for (byte b : out) {
                sb.append(String.format(Locale.ROOT, "%02x", b));
            }
            return sb.toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }
}
