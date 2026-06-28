package dev.hg.grantmint.server.audit;

import java.util.Locale;

/**
 * Who performed an audited action. Persisted as lowercase {@code text} guarded by the
 * {@code ck_audit_actor_type} CHECK constraint.
 */
public enum AuditActorType {
    ADMIN,
    API_KEY,
    WEBHOOK,
    SYSTEM;

    /** The lowercase token stored in {@code audit_log.actor_type}. */
    public String wire() {
        return name().toLowerCase(Locale.ROOT);
    }
}
