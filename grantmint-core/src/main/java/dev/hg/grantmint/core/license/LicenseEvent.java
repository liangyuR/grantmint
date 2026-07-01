package dev.hg.grantmint.core.license;

/**
 * The lifecycle events that drive {@link LicenseStateMachine}. {@code start_trial} from the
 * transition table is mechanically an {@link #ACTIVATE} (a trial is an ACTIVE license with a trial
 * flag and a short token exp, not a separate state). See docs/features/LICENSE_LIFECYCLE.md.
 */
public enum LicenseEvent {
    /** First online contact (or trial start): CREATED → ACTIVE. */
    ACTIVATE,
    /** Trial becomes paid: stays ACTIVE (the only self-loop; flag clears, token re-issued). */
    CONVERT_TRIAL,
    /** Payment failure / dispute: ACTIVE → SUSPENDED (recoverable). */
    SUSPEND,
    /** Recovery from suspension: SUSPENDED → ACTIVE. */
    REINSTATE,
    /** Validity window elapsed (sweep job): CREATED/ACTIVE/SUSPENDED → EXPIRED. */
    EXPIRE,
    /** Renewal with a new expiry: EXPIRED → ACTIVE (re-issued token carries the new exp). */
    RENEW,
    /** Permanent kill: any non-revoked state → REVOKED. Terminal — there is no un-revoke. */
    REVOKE
}
