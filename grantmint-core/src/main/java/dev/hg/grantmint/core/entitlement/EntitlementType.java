package dev.hg.grantmint.core.entitlement;

/**
 * The three kinds of entitlement that can ride in a token's {@code ent} claim.
 *
 * <ul>
 *   <li>{@link #FLAG} — a boolean capability ({@code team_sync}); fully resolvable offline.
 *   <li>{@link #LIMIT} — an integer ceiling ({@code max_devices}); the ceiling is offline, but
 *       enforcing a live count against it (seat counting) is an online concern. {@code -1} means
 *       unlimited.
 *   <li>{@link #STRING} — a string-valued capability ({@code support_tier="gold"}).
 * </ul>
 *
 * <p>See docs/features/ENTITLEMENTS.md.
 */
public enum EntitlementType {
    FLAG,
    LIMIT,
    STRING
}
