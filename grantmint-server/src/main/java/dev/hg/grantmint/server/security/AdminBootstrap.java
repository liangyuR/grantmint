package dev.hg.grantmint.server.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Seeds the bootstrap operator on first start with an empty {@code admin_users} table, reading the
 * username/password from {@code grantmint.admin.*} (typically {@code GRANTMINT_ADMIN_USERNAME} /
 * {@code GRANTMINT_ADMIN_PASSWORD}). A no-op once any operator exists. See
 * docs/features/ADMIN_AND_API_AUTH.md.
 */
@Component
public class AdminBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminBootstrap.class);

    private final AdminUserService adminUsers;
    private final GrantmintAdminProperties properties;

    public AdminBootstrap(AdminUserService adminUsers, GrantmintAdminProperties properties) {
        this.adminUsers = adminUsers;
        this.properties = properties;
    }

    @Override
    public void run(ApplicationArguments args) {
        String username = properties.username();
        String password = properties.password();
        if (password == null || password.isBlank()) {
            log.info("No grantmint.admin.password set; skipping admin bootstrap. "
                    + "Set GRANTMINT_ADMIN_PASSWORD on first boot to seed an operator.");
            return;
        }
        adminUsers
                .bootstrapIfEmpty(username, password)
                .ifPresent(admin -> log.warn(
                        "Bootstrapped admin '{}' from configuration. Change this password immediately via "
                                + "POST /admin/auth/password.",
                        admin.getUsername()));
    }
}
