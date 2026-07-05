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
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
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

    /**
     * Exchange username/password for an opaque session bearer token. Open (no auth required).
     *
     * <p>The return type is deliberately {@code ResponseEntity<LoginResponse>}, not a wildcard:
     * Spring AOT derives the native-image Jackson hints from this signature, and a {@code <?>}
     * here shipped a native binary whose login responded 406 (GRANTMINT-119). The 401 path goes
     * through {@link ApiExceptionHandler} instead of a second body type.
     */
    @PostMapping("/login")
    @Operation(summary = "Log in", description = "Exchange username/password for a session bearer token. Open.")
    ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        Optional<LoginResult> result = sessions.login(request.username(), request.password());
        if (result.isEmpty()) {
            throw new BadCredentialsException("Invalid username or password.");
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

    /**
     * Change the calling operator's password (re-hashed with Argon2id). Requires re-entering the
     * current password — a session token alone must not be able to rotate the credential, or a
     * hijacked/XSS'd session could lock the real operator out (M13 audit hardening). On success
     * every live session is revoked, the standard consequence of credential rotation: whoever
     * holds the new password logs back in; whoever merely held a session token is out.
     */
    @PostMapping("/password")
    @Operation(
            summary = "Change the current operator's password",
            description = "Requires the current password; revokes all sessions on success — log in again.")
    @SecurityRequirement(name = OpenApiConfig.ADMIN_SESSION)
    ResponseEntity<Void> changePassword(
            @AuthenticationPrincipal AdminPrincipal principal,
            @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest) {
        String newPassword = request.newPassword();
        if (newPassword == null || newPassword.length() < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
        }
        if (request.currentPassword() == null
                || adminUsers
                        .authenticate(principal.username(), request.currentPassword())
                        .isEmpty()) {
            throw new BadCredentialsException("Current password is incorrect.");
        }
        adminUsers.changePassword(principal.adminUserId(), newPassword);
        sessions.logoutAll(principal.adminUserId());
        audit.record(
                principal.username(),
                AuditActorType.ADMIN,
                "admin.password_changed",
                "admin_user",
                principal.username(),
                Map.of(),
                httpRequest.getRemoteAddr());
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, sessionCookie("", Duration.ZERO))
                .build();
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

    /**
     * @param currentPassword the operator's current password — proof of credential, not just session
     * @param newPassword the replacement plaintext password
     */
    public record ChangePasswordRequest(String currentPassword, String newPassword) {}

    /**
     * @param token the opaque {@code gm_sess_…} session token, shown once
     * @param expiresAt absolute expiry
     * @param admin the authenticated operator
     */
    public record LoginResponse(String token, OffsetDateTime expiresAt, AdminSummary admin) {}

    /** @param username the operator's username */
    public record AdminSummary(String username) {}
}
