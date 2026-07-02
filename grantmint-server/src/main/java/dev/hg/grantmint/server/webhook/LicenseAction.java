package dev.hg.grantmint.server.webhook;

/**
 * The ONLY effects a webhook may have — licensing, never money. There is deliberately no "charge",
 * "refund", or "capture" variant: the payment provider already moved the money; Grantmint only
 * changes license state in response. Sealed so the executor's handling is exhaustive by
 * construction. See docs/features/WEBHOOK_INTEGRATION.md.
 */
public sealed interface LicenseAction {

    /**
     * Mint a new license from the policy identified by {@code policyKey} (a Grantmint policy code,
     * resolved from the provider price id via the configured policy-map) for the holder, tied to
     * the provider object via {@code externalRef} (subscription/customer id).
     */
    record IssueLicense(String policyKey, Holder holder, String externalRef) implements LicenseAction {}

    /** Suspend the license(s) tied to {@code externalRef} (recoverable) — e.g. payment failed. */
    record SuspendLicense(String externalRef, String reason) implements LicenseAction {}

    /** Reinstate previously suspended license(s) — e.g. payment recovered. No-op when not suspended. */
    record ReinstateLicense(String externalRef) implements LicenseAction {}

    /** Expire the license(s) tied to {@code externalRef} — e.g. subscription cancelled or refunded. */
    record ExpireLicense(String externalRef) implements LicenseAction {}

    /** Recognized but no licensing effect — kept for audit/visibility, answered with HTTP 200. */
    record Ignore(String reason) implements LicenseAction {}

    /** The licensee as the provider reported it. */
    record Holder(String name, String email) {}
}
