package dev.hg.grantmint.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

/**
 * Entry point for the Grantmint license &amp; entitlement server.
 *
 * <p>The application wires the REST API, JPA persistence, the three Spring Security auth
 * schemes, the Caffeine validation cache, payment-webhook adapters, and the scheduled
 * lifecycle jobs. Those layers arrive in later milestones.
 *
 * <p>{@link UserDetailsServiceAutoConfiguration} is excluded: authentication is fully custom
 * (API-key and admin-session filters), so Spring's default in-memory user with a generated
 * password would be dead weight and misleading noise.
 */
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
public class GrantmintServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(GrantmintServerApplication.class, args);
    }
}
