package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.security.AdminPrincipal;
import dev.hg.grantmint.server.security.AdminSessionService;
import dev.hg.grantmint.server.security.AdminSessionService.LoginResult;
import dev.hg.grantmint.server.security.AdminUserService;
import dev.hg.grantmint.server.security.BearerTokens;
import jakarta.servlet.http.HttpServletRequest;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Scheme 1 admin auth endpoints: login (open), and the authenticated session-management actions
 * (logout, log out everywhere, change password). See docs/features/ADMIN_AND_API_AUTH.md.
 */
@RestController
@RequestMapping("/admin/auth")
public class AdminAuthController {

    /** Minimum admin password length enforced on change. */
    private static final int MIN_PASSWORD_LENGTH = 8;

    private final AdminSessionService sessions;
    private final AdminUserService adminUsers;
    private final AuditService audit;

    public AdminAuthController(AdminSessionService sessions, AdminUserService adminUsers, AuditService audit) {
        this.sessions = sessions;
        this.adminUsers = adminUsers;
        this.audit = audit;
    }

    /** Exchange username/password for an opaque session bearer token. Open (no auth required). */
    @PostMapping("/login")
    ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        Optional<LoginResult> result = sessions.login(request.username(), request.password());
        if (result.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiError("unauthorized", "Invalid username or password."));
        }
        LoginResult session = result.get();
        audit.record(
                session.username(),
                AuditActorType.ADMIN,
                "admin.login",
                "admin_user",
                session.username(),
                Map.of(),
                httpRequest.getRemoteAddr());
        return ResponseEntity.ok(
                new LoginResponse(session.token(), session.expiresAt(), new AdminSummary(session.username())));
    }

    /** Revoke the presented session (log out this client). */
    @PostMapping("/logout")
    ResponseEntity<Void> logout(HttpServletRequest httpRequest) {
        String token = BearerTokens.extract(httpRequest);
        sessions.logout(token);
        return ResponseEntity.noContent().build();
    }

    /** Revoke every live session for the calling operator ("log out everywhere"). */
    @PostMapping("/logout-all")
    ResponseEntity<Void> logoutAll(@AuthenticationPrincipal AdminPrincipal principal) {
        sessions.logoutAll(principal.adminUserId());
        return ResponseEntity.noContent().build();
    }

    /** Change the calling operator's password (re-hashed with Argon2id). */
    @PostMapping("/password")
    ResponseEntity<Void> changePassword(
            @AuthenticationPrincipal AdminPrincipal principal, @RequestBody ChangePasswordRequest request) {
        String newPassword = request.newPassword();
        if (newPassword == null || newPassword.length() < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
        }
        adminUsers.changePassword(principal.adminUserId(), newPassword);
        return ResponseEntity.noContent().build();
    }

    /** @param username the operator's username @param password the plaintext password */
    public record LoginRequest(String username, String password) {}

    /** @param newPassword the replacement plaintext password */
    public record ChangePasswordRequest(String newPassword) {}

    /**
     * @param token the opaque {@code gm_sess_…} session token, shown once
     * @param expiresAt absolute expiry
     * @param admin the authenticated operator
     */
    public record LoginResponse(String token, OffsetDateTime expiresAt, AdminSummary admin) {}

    /** @param username the operator's username */
    public record AdminSummary(String username) {}
}
