package dev.hg.grantmint.core.license;

import java.util.EnumSet;
import java.util.Set;

/**
 * The guarded license lifecycle — the transition table of docs/features/LICENSE_LIFECYCLE.md as
 * code, one entry per event. Framework-free by design: the server layer applies an event and
 * persists the result; this class only decides legality.
 *
 * <p>Enforcement is per-<em>event</em>, stricter than target reachability alone: EXPIRED may return
 * to ACTIVE, but only through {@link LicenseEvent#RENEW} (a renewal mints a new expiry) — a
 * {@link LicenseEvent#REINSTATE}, legal only from SUSPENDED, must not resurrect an expired license.
 * {@link LicenseEvent#CONVERT_TRIAL} is the one self-loop: a trial converts to paid without leaving
 * ACTIVE. Every state-changing edge here is consistent with {@link LicenseState#allowedTargets()};
 * nothing leaves REVOKED.
 */
public final class LicenseStateMachine {

    /**
     * Apply a lifecycle event, returning the new state.
     *
     * @throws IllegalLicenseTransitionException if the event is not legal from the current state
     */
    public LicenseState apply(LicenseState current, LicenseEvent event) {
        if (!allowedFrom(event).contains(current)) {
            throw new IllegalLicenseTransitionException(current, event);
        }
        return targetOf(event);
    }

    /** Whether the event may be applied in the current state (the non-throwing probe). */
    public boolean permits(LicenseState current, LicenseEvent event) {
        return allowedFrom(event).contains(current);
    }

    /** The state every occurrence of this event lands in. */
    public static LicenseState targetOf(LicenseEvent event) {
        return switch (event) {
            case ACTIVATE, CONVERT_TRIAL, REINSTATE, RENEW -> LicenseState.ACTIVE;
            case SUSPEND -> LicenseState.SUSPENDED;
            case EXPIRE -> LicenseState.EXPIRED;
            case REVOKE -> LicenseState.REVOKED;
        };
    }

    /** The exact from-states each event is legal in — the transition table, verbatim. */
    public static Set<LicenseState> allowedFrom(LicenseEvent event) {
        return switch (event) {
            case ACTIVATE -> EnumSet.of(LicenseState.CREATED);
            case CONVERT_TRIAL -> EnumSet.of(LicenseState.ACTIVE);
            case SUSPEND -> EnumSet.of(LicenseState.ACTIVE);
            case REINSTATE -> EnumSet.of(LicenseState.SUSPENDED);
            case EXPIRE -> EnumSet.of(LicenseState.CREATED, LicenseState.ACTIVE, LicenseState.SUSPENDED);
            case RENEW -> EnumSet.of(LicenseState.EXPIRED);
            case REVOKE -> EnumSet.of(
                    LicenseState.CREATED, LicenseState.ACTIVE, LicenseState.SUSPENDED, LicenseState.EXPIRED);
        };
    }
}
