package dev.hg.grantmint.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Grantmint license &amp; entitlement server.
 *
 * <p>The application wires the REST API, JPA persistence, the three Spring Security auth
 * schemes, the Caffeine validation cache, payment-webhook adapters, and the scheduled
 * lifecycle jobs. Those layers arrive in later milestones; this is the M0 boot skeleton.
 */
@SpringBootApplication
public class GrantmintServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(GrantmintServerApplication.class, args);
    }
}
