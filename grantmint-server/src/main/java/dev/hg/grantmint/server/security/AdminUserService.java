package dev.hg.grantmint.server.security;

import dev.hg.grantmint.server.domain.AdminUser;
import dev.hg.grantmint.server.repo.AdminUserRepository;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Operator accounts for Scheme 1. Passwords are hashed with Argon2id and verified in the encoder's
 * own constant-time compare; the plaintext is never stored. See docs/features/ADMIN_AND_API_AUTH.md.
 */
@Service
public class AdminUserService {

    private final AdminUserRepository admins;
    private final PasswordEncoder passwordEncoder;

    public AdminUserService(AdminUserRepository admins, PasswordEncoder passwordEncoder) {
        this.admins = admins;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Seed the bootstrap operator when {@code admin_users} is empty. A no-op once any operator
     * exists, so it is safe to run on every start.
     *
     * @return the created admin, or empty if one already existed or no password was supplied
     */
    @Transactional
    public Optional<AdminUser> bootstrapIfEmpty(String username, String rawPassword) {
        if (rawPassword == null || rawPassword.isBlank()) {
            return Optional.empty();
        }
        if (admins.count() > 0) {
            return Optional.empty();
        }
        AdminUser admin = new AdminUser();
        admin.setUsername(username);
        admin.setPasswordHash(passwordEncoder.encode(rawPassword));
        return Optional.of(admins.save(admin));
    }

    /**
     * Verify a username/password pair. Returns the operator on success, empty on any failure
     * (unknown user, disabled, or wrong password) — callers must not distinguish these to the client.
     */
    @Transactional(readOnly = true)
    public Optional<AdminUser> authenticate(String username, String rawPassword) {
        if (username == null || rawPassword == null) {
            return Optional.empty();
        }
        return admins.findByUsername(username)
                .filter(admin -> admin.getDisabledAt() == null)
                .filter(admin -> passwordEncoder.matches(rawPassword, admin.getPasswordHash()));
    }

    /**
     * Re-hash and store a new password for an operator.
     *
     * @throws java.util.NoSuchElementException if the operator does not exist
     */
    @Transactional
    public void changePassword(UUID adminUserId, String newRawPassword) {
        AdminUser admin = admins.findById(adminUserId).orElseThrow();
        admin.setPasswordHash(passwordEncoder.encode(newRawPassword));
    }
}
