package dev.hg.grantmint.core.license;

import java.util.EnumSet;
import java.util.Set;

/**
 * The five license lifecycle states. A license is in exactly one; the only terminal state is
 * {@link #REVOKED}. See docs/features/LICENSE_LIFECYCLE.md (state machine + transition table).
 */
public enum LicenseState {
    CREATED,
    ACTIVE,
    SUSPENDED,
    EXPIRED,
    REVOKED;

    /**
     * The state <em>changes</em> ever reachable from this state, regardless of which event drives
     * them. REVOKED maps to the empty set — "revocation is terminal" as a compile-checked invariant,
     * not a comment. Which event may cause which change (e.g. EXPIRED returns to ACTIVE only via
     * {@code RENEW}, never {@code REINSTATE}) is enforced by {@link LicenseStateMachine}.
     */
    public Set<LicenseState> allowedTargets() {
        return switch (this) {
            case CREATED -> EnumSet.of(ACTIVE, EXPIRED, REVOKED);
            case ACTIVE -> EnumSet.of(SUSPENDED, EXPIRED, REVOKED);
            case SUSPENDED -> EnumSet.of(ACTIVE, EXPIRED, REVOKED);
            case EXPIRED -> EnumSet.of(ACTIVE, REVOKED); // ACTIVE only via renewal (new exp)
            case REVOKED -> EnumSet.noneOf(LicenseState.class); // terminal
        };
    }

    public boolean canTransitionTo(LicenseState target) {
        return allowedTargets().contains(target);
    }
}
