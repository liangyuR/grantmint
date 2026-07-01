package dev.hg.grantmint.server.audit;

import dev.hg.grantmint.server.domain.AuditLog;
import dev.hg.grantmint.server.repo.AuditLogRepository;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Append-only writer for the audit trail. Records "who did what to which target" for every
 * mintable action (issue/suspend/reinstate/revoke, key creation, etc.).
 *
 * <p>The trail is deliberately append-only — this service exposes no update or delete. Audit rows
 * use a loose {@code (target_type, target_id)} reference with no foreign key, so they survive
 * deletion of the target they describe. See docs/architecture/DATABASE_SCHEMA.md.
 */
@Service
public class AuditService {

    /** Strict IPv4 dotted-quad (each octet 0–255). */
    private static final Pattern IPV4 = Pattern.compile(
            "^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$");

    private final AuditLogRepository repository;

    public AuditService(AuditLogRepository repository) {
        this.repository = repository;
    }

    /**
     * Append an audit entry, capturing the originating request IP. Participates in the caller's
     * transaction so the trail stays consistent with the action it records (if the action rolls back,
     * so does its audit row).
     *
     * @param actor who acted — an admin username, an API-key id, or e.g. {@code webhook:stripe}
     * @param actorType the category of actor
     * @param action the action performed, e.g. {@code license.issued}
     * @param targetType the kind of entity acted upon, e.g. {@code license}
     * @param targetId the target's identifier (nullable for non-entity actions)
     * @param detail action-specific structured data (nullable → recorded as empty)
     * @param ipAddress the originating request IP (nullable for system/background actions); stored as
     *     PostgreSQL {@code inet}
     */
    @Transactional
    public AuditLog record(
            String actor,
            AuditActorType actorType,
            String action,
            String targetType,
            String targetId,
            Map<String, Object> detail,
            String ipAddress) {
        AuditLog entry = new AuditLog();
        entry.setActor(actor);
        entry.setActorType(actorType.wire());
        entry.setAction(action);
        entry.setTargetType(targetType);
        entry.setTargetId(targetId);
        if (detail != null && !detail.isEmpty()) {
            entry.setDetail(detail);
        }
        entry.setIpAddress(normalizeIpOrNull(ipAddress));
        return repository.save(entry);
    }

    /**
     * Coerce an IP string to a valid IPv4/IPv6 literal or {@code null}. The {@code ip_address} column
     * is PostgreSQL {@code inet}; a malformed value would otherwise fail the INSERT at the database
     * layer and lose the audit row. An audit write must never be defeated by a bad IP, so an invalid
     * value is dropped to {@code null} rather than thrown. Validation is DNS-free: IPv4 is matched by
     * pattern, and any string containing a colon is parsed as an IPv6 literal (a colon can never
     * appear in a hostname, so {@link InetAddress#getByName} performs no name resolution).
     */
    public static String normalizeIpOrNull(String ipAddress) {
        if (ipAddress == null) {
            return null;
        }
        String trimmed = ipAddress.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        if (IPV4.matcher(trimmed).matches()) {
            return trimmed;
        }
        if (trimmed.indexOf(':') >= 0) {
            try {
                InetAddress.getByName(trimmed); // colon ⇒ IPv6 literal parse only, never a DNS lookup
                return trimmed;
            } catch (UnknownHostException malformed) {
                return null;
            }
        }
        return null;
    }

    /** Overload for actions where the request IP is not available (e.g. background jobs). */
    @Transactional
    public AuditLog record(
            String actor,
            AuditActorType actorType,
            String action,
            String targetType,
            String targetId,
            Map<String, Object> detail) {
        return record(actor, actorType, action, targetType, targetId, detail, null);
    }

    /** Convenience overload for actions with no structured detail. */
    @Transactional
    public AuditLog record(String actor, AuditActorType actorType, String action, String targetType, String targetId) {
        return record(actor, actorType, action, targetType, targetId, Map.of(), null);
    }
}
