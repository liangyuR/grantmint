package dev.hg.grantmint.server.webhook;

/**
 * The webhook's provider signature failed verification — malformed header, HMAC mismatch, or a
 * timestamp outside the replay-tolerance window. Always rendered as HTTP 400 and never acted upon:
 * the signature is this surface's <em>only</em> authentication.
 */
public class WebhookSignatureException extends Exception {

    public WebhookSignatureException(String message) {
        super(message);
    }
}
