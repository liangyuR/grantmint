package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.security.AdminPrincipal;
import dev.hg.grantmint.server.security.AdminSessionAuthFilter;
import dev.hg.grantmint.server.security.AdminSessionService;
import dev.hg.grantmint.server.security.AdminSessionService.LoginResult;
import dev.hg.grantmint.server.security.AdminUserService;
import dev.hg.grantmint.server.security.GrantmintAdminProperties;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
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
@Tag(name = "Admin auth", description = "Scheme 1 — admin login and session management.")
public class AdminAuthController {

    /** Minimum admin password length enforced on change. */
    private static final int MIN_PASSWORD_LENGTH = 8;

    private final AdminSessionService sessions;
    private final AdminUserService adminUsers;
    private final AuditService audit;
    private final GrantmintAdminProperties properties;

    public AdminAuthController(
            AdminSessionService sessions,
            AdminUserService adminUsers,
            AuditService audit,
            GrantmintAdminProperties properties) {
        this.sessions = sessions;
        this.adminUsers = adminUsers;
        this.audit = audit;
        this.properties = properties;
    }

    /** Exchange username/password for an opaque session bearer token. Open (no auth required). */
    @PostMapping("/login")
    @Operation(summary = "Log in", description = "Exchange username/password for a session bearer token. Open.")
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
        // Dual delivery: the JSON body carries the token for bearer clients (CLI/API); the
        // HttpOnly SameSite=Strict cookie carries it for the browser dashboard, where JS must
        // never be able to read it. SameSite=Strict is also the primary login-CSRF defence.
        return ResponseEntity.ok()
                .header(
                        HttpHeaders.SET_COOKIE,
                        sessionCookie(session.token(), properties.session().ttl()))
                .body(new LoginResponse(session.token(), session.expiresAt(), new AdminSummary(session.username())));
    }

    /** Revoke the presented session (log out this client), however it was carried. */
    @PostMapping("/logout")
    @Operation(summary = "Log out (revoke this session)")
    @SecurityRequirement(name = OpenApiConfig.ADMIN_SESSION)
    ResponseEntity<Void> logout(HttpServletRequest httpRequest) {
        String token = AdminSessionAuthFilter.presentedToken(httpRequest, properties);
        sessions.logout(token);
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, sessionCookie("", Duration.ZERO))
                .build();
    }

    /** Revoke every live session for the calling operator ("log out everywhere"). */
    @PostMapping("/logout-all")
    @Operation(summary = "Log out everywhere (revoke all sessions)")
    @SecurityRequirement(name = OpenApiConfig.ADMIN_SESSION)
    ResponseEntity<Void> logoutAll(@AuthenticationPrincipal AdminPrincipal principal) {
        sessions.logoutAll(principal.adminUserId());
        return ResponseEntity.noContent().build();
    }

    /** Change the calling operator's password (re-hashed with Argon2id). */
    @PostMapping("/password")
    @Operation(summary = "Change the current operator's password")
    @SecurityRequirement(name = OpenApiConfig.ADMIN_SESSION)
    ResponseEntity<Void> changePassword(
            @AuthenticationPrincipal AdminPrincipal principal, @RequestBody ChangePasswordRequest request) {
        String newPassword = request.newPassword();
        if (newPassword == null || newPassword.length() < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
        }
        adminUsers.changePassword(principal.adminUserId(), newPassword);
        return ResponseEntity.noContent().build();
    }

    /** The session cookie: HttpOnly (JS never reads it) + SameSite=Strict (login-CSRF defence). */
    private String sessionCookie(String value, Duration maxAge) {
        return ResponseCookie.from(properties.session().cookieName(), value)
                .httpOnly(true)
                .secure(properties.session().cookieSecure())
                .sameSite("Strict")
                .path("/")
                .maxAge(maxAge)
                .build()
                .toString();
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
