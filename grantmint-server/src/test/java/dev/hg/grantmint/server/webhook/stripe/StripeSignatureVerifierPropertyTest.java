package dev.hg.grantmint.server.webhook.stripe;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.grantmint.server.webhook.WebhookRequest;
import dev.hg.grantmint.server.webhook.WebhookSignatureException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.LongRange;
import net.jqwik.api.constraints.NotBlank;
import net.jqwik.api.constraints.Size;
import net.jqwik.api.constraints.StringLength;

/**
 * Property proof of the webhook surface's only authentication: for ANY body and secret, a correctly
 * signed request verifies; any single-byte tampering of the body, a wrong secret, or a timestamp
 * outside the tolerance window is rejected. This HMAC is the gate in front of every
 * license-mutating webhook action — see docs/features/WEBHOOK_INTEGRATION.md (signature
 * verification, the three non-negotiables).
 */
class StripeSignatureVerifierPropertyTest {

    private static final Instant NOW = Instant.parse("2026-06-28T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final Duration TOLERANCE = Duration.ofSeconds(300);

    @Property(tries = 500)
    void anyCorrectlySignedBodyVerifies(
            @ForAll @NotBlank @StringLength(min = 8, max = 64) String secret, @ForAll @Size(max = 512) byte[] body) {
        StripeSignatureVerifier verifier = new StripeSignatureVerifier(secret, TOLERANCE, CLOCK);

        assertThatCode(() -> verifier.verify(signed(secret, body, NOW.getEpochSecond())))
                .doesNotThrowAnyException();
    }

    @Property(tries = 500)
    void anySingleByteTamperingIsRejected(
            @ForAll @NotBlank @StringLength(min = 8, max = 64) String secret,
            @ForAll @Size(min = 1, max = 512) byte[] body,
            @ForAll @IntRange(min = 0, max = 511) int flipIndex,
            @ForAll @IntRange(min = 0, max = 7) int flipBit) {
        StripeSignatureVerifier verifier = new StripeSignatureVerifier(secret, TOLERANCE, CLOCK);
        WebhookRequest request = signed(secret, body, NOW.getEpochSecond());

        byte[] tampered = body.clone();
        tampered[flipIndex % body.length] ^= (byte) (1 << flipBit);
        WebhookRequest forged = new WebhookRequest(tampered, request.headers());

        assertThatThrownBy(() -> verifier.verify(forged))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("signature mismatch");
    }

    @Property(tries = 300)
    void aWrongSecretIsRejected(
            @ForAll @NotBlank @StringLength(min = 8, max = 64) String secret,
            @ForAll @NotBlank @StringLength(min = 8, max = 64) String otherSecret,
            @ForAll @Size(max = 256) byte[] body) {
        if (secret.equals(otherSecret)) {
            return;
        }
        StripeSignatureVerifier verifier = new StripeSignatureVerifier(secret, TOLERANCE, CLOCK);

        assertThatThrownBy(() -> verifier.verify(signed(otherSecret, body, NOW.getEpochSecond())))
                .isInstanceOf(WebhookSignatureException.class);
    }

    /** The replay defense: a valid signature whose timestamp fell out of the window is dead. */
    @Property(tries = 300)
    void anyTimestampOutsideToleranceIsRejected(
            @ForAll @NotBlank @StringLength(min = 8, max = 32) String secret,
            @ForAll @Size(max = 128) byte[] body,
            @ForAll @LongRange(min = 301, max = 1_000_000) long skewSeconds,
            @ForAll boolean past) {
        StripeSignatureVerifier verifier = new StripeSignatureVerifier(secret, TOLERANCE, CLOCK);
        long t = past ? NOW.getEpochSecond() - skewSeconds : NOW.getEpochSecond() + skewSeconds;

        assertThatThrownBy(() -> verifier.verify(signed(secret, body, t)))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("tolerance");
    }

    /**
     * An absent Stripe-Signature header is an unauthenticated request and must surface as the same
     * clean {@link WebhookSignatureException} (→ 400) as a bad signature — never an NPE/500. Safe
     * today because {@link WebhookRequest#header} returns {@code ""} for a missing name; this pin
     * keeps that contract from regressing (flagged by the post-M13 audit as a suspected NPE).
     */
    @Property(tries = 100)
    void aMissingSignatureHeaderIsRejectedNotAnNpe(
            @ForAll @NotBlank @StringLength(min = 8, max = 32) String secret, @ForAll @Size(max = 128) byte[] body) {
        StripeSignatureVerifier verifier = new StripeSignatureVerifier(secret, TOLERANCE, CLOCK);

        assertThatThrownBy(() -> verifier.verify(new WebhookRequest(body, Map.of())))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("malformed Stripe-Signature header");
    }

    @Property(tries = 200)
    void rotationHeadersWithOneValidV1AmongInvalidOnesVerify(
            @ForAll @NotBlank @StringLength(min = 8, max = 32) String secret, @ForAll @Size(max = 128) byte[] body) {
        StripeSignatureVerifier verifier = new StripeSignatureVerifier(secret, TOLERANCE, CLOCK);
        long t = NOW.getEpochSecond();
        String valid = hmacHex(secret, t, body);
        String header = "t=" + t + ",v1=" + "0".repeat(64) + ",v1=" + valid;

        assertThatCode(() -> verifier.verify(new WebhookRequest(body, Map.of("Stripe-Signature", header))))
                .doesNotThrowAnyException();
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private static WebhookRequest signed(String secret, byte[] body, long timestamp) {
        String header = "t=" + timestamp + ",v1=" + hmacHex(secret, timestamp, body);
        return new WebhookRequest(body, Map.of("Stripe-Signature", header));
    }

    private static String hmacHex(String secret, long timestamp, byte[] body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update((timestamp + ".").getBytes(StandardCharsets.UTF_8));
            byte[] out = mac.doFinal(body);
            StringBuilder sb = new StringBuilder(out.length * 2);
            for (byte b : out) {
                sb.append(String.format(Locale.ROOT, "%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
