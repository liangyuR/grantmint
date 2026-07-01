package dev.hg.grantmint.core.license;

/**
 * An event was applied to a state it is not legal from — e.g. reinstating a revoked license or
 * suspending one that was never activated. Thrown (never silently ignored) so a bug can never
 * un-revoke a license or skip a state: a license that changes state when it shouldn't is a broken
 * product. See docs/features/LICENSE_LIFECYCLE.md.
 */
public class IllegalLicenseTransitionException extends RuntimeException {

    private final LicenseState from;
    private final LicenseEvent event;

    public IllegalLicenseTransitionException(LicenseState from, LicenseEvent event) {
        super("Illegal license transition: event " + event + " is not allowed from state " + from);
        this.from = from;
        this.event = event;
    }

    public LicenseState from() {
        return from;
    }

    public LicenseEvent event() {
        return event;
    }
}
