package dev.hg.grantmint.server.security;

import dev.hg.grantmint.server.domain.AdminSession;
import dev.hg.grantmint.server.domain.AdminUser;
import dev.hg.grantmint.server.repo.AdminSessionRepository;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Issues, resolves, and revokes opaque server-side admin sessions (Scheme 1).
 *
 * <p>A successful login mints a {@code gm_sess_…} bearer token; only its SHA-256 hash is stored.
 * Resolution hashes the presented token, looks it up, re-compares in constant time, and rejects
 * revoked or expired sessions. Because sessions are server-side, the operator can revoke any one
 * instantly. See docs/features/ADMIN_AND_API_AUTH.md.
 */
@Service
public class AdminSessionService {

    /** Namespace prefix for admin session bearer tokens. */
    static final String SESSION_PREFIX = "gm_sess_";

    private final AdminSessionRepository sessions;
    private final AdminUserService adminUsers;
    private final GrantmintAdminProperties properties;
    private final Clock clock;

    public AdminSessionService(
            AdminSessionRepository sessions,
            AdminUserService adminUsers,
            GrantmintAdminProperties properties,
            Clock clock) {
        this.sessions = sessions;
        this.adminUsers = adminUsers;
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * Verify credentials and, on success, mint a session. The returned {@link LoginResult#token()}
     * is the only copy of the secret — it is never persisted.
     *
     * @return the new session, or empty if the credentials are invalid
     */
    @Transactional
    public Optional<LoginResult> login(String username, String rawPassword) {
        return adminUsers.authenticate(username, rawPassword).map(admin -> {
            String token = SESSION_PREFIX + Secrets.randomTokenHex();
            OffsetDateTime now = OffsetDateTime.now(clock);
            OffsetDateTime expiresAt = now.plus(properties.session().ttl());

            AdminSession session = new AdminSession();
            session.setAdminUser(admin);
            session.setTokenHash(Secrets.sha256Hex(token));
            session.setLastUsedAt(now);
            session.setExpiresAt(expiresAt);
            sessions.save(session);

            return new LoginResult(token, expiresAt, admin.getUsername());
        });
    }

    /**
     * Resolve a presented session token to its operator. Returns empty for any failure (unknown,
     * revoked, or expired) and touches {@code last_used_at} on success.
     */
    @Transactional
    public Optional<AdminPrincipal> resolve(String token) {
        if (token == null || !token.startsWith(SESSION_PREFIX)) {
            return Optional.empty();
        }
        String tokenHash = Secrets.sha256Hex(token);
        Optional<AdminSession> found = sessions.findByTokenHash(tokenHash);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        AdminSession session = found.get();
        if (!Secrets.constantTimeEqualsHex(tokenHash, session.getTokenHash())) {
            return Optional.empty();
        }
        OffsetDateTime now = OffsetDateTime.now(clock);
        if (session.getRevokedAt() != null || !session.getExpiresAt().isAfter(now)) {
            return Optional.empty();
        }
        session.setLastUsedAt(now);
        AdminUser admin = session.getAdminUser();
        return Optional.of(new AdminPrincipal(admin.getId(), admin.getUsername()));
    }

    /** Revoke the session backing a presented token (log out). Idempotent and silent if unknown. */
    @Transactional
    public void logout(String token) {
        if (token == null || !token.startsWith(SESSION_PREFIX)) {
            return;
        }
        sessions.findByTokenHash(Secrets.sha256Hex(token)).ifPresent(session -> {
            if (session.getRevokedAt() == null) {
                session.setRevokedAt(OffsetDateTime.now(clock));
            }
        });
    }

    /** Revoke every live session for an operator ("log out everywhere"). */
    @Transactional
    public int logoutAll(UUID adminUserId) {
        return sessions.revokeAllForUser(adminUserId, OffsetDateTime.now(clock));
    }

    /**
     * A freshly minted session.
     *
     * @param token the opaque {@code gm_sess_…} bearer token, shown once
     * @param expiresAt absolute expiry
     * @param username the operator's username
     */
    public record LoginResult(String token, OffsetDateTime expiresAt, String username) {}
}
