package dev.hg.grantmint.server.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Startup guardrail for the management port's bind address. The loopback default keeps a bare-JAR
 * deployment from exposing {@code /actuator/prometheus} (capacity, product slugs, license counts)
 * on all interfaces by accident; overriding {@code GRANTMINT_MANAGEMENT_ADDRESS} to a non-loopback
 * bind is legitimate (containers need it — Docker's port mapping targets the container IP), but it
 * must be a visible decision, not a silent one (post-M13 audit). One WARN at ready-time; the
 * control itself stays application.yml + the deployment's firewall/port mapping.
 */
@Component
public class ManagementBindWarning {

    private static final Logger log = LoggerFactory.getLogger(ManagementBindWarning.class);

    private final String managementAddress;

    public ManagementBindWarning(@Value("${management.server.address:127.0.0.1}") String managementAddress) {
        this.managementAddress = managementAddress;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void warnWhenManagementBindIsNotLoopback() {
        if (!isLoopback(managementAddress)) {
            log.warn(
                    "management port is bound to {} (not loopback) — /actuator/prometheus exposes capacity and "
                            + "license counts; make sure this port is scoped to a private metrics network "
                            + "(docs/operations/MONITORING_LOGGING.md)",
                    managementAddress);
        }
    }

    /**
     * Literal loopback spellings only — no DNS resolution at startup. An unrecognized value is
     * treated as non-loopback: over-warning is the safe failure mode for a guardrail.
     */
    static boolean isLoopback(String address) {
        if (address == null || address.isBlank()) {
            return false;
        }
        String trimmed = address.strip();
        return trimmed.equals("127.0.0.1")
                || trimmed.startsWith("127.")
                || trimmed.equals("::1")
                || trimmed.equals("0:0:0:0:0:0:0:1")
                || trimmed.equalsIgnoreCase("localhost");
    }
}
