package dev.hg.grantmint.server.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * The bind-address classifier behind the startup guardrail: loopback spellings stay silent, any
 * exposed or unrecognized bind warns. No DNS resolution, so the classification is a pure string
 * decision (over-warning is the safe failure mode).
 */
class ManagementBindWarningTest {

    @Test
    void loopbackSpellingsAreRecognized() {
        assertThat(ManagementBindWarning.isLoopback("127.0.0.1")).isTrue();
        assertThat(ManagementBindWarning.isLoopback("127.0.1.1")).isTrue();
        assertThat(ManagementBindWarning.isLoopback("::1")).isTrue();
        assertThat(ManagementBindWarning.isLoopback("0:0:0:0:0:0:0:1")).isTrue();
        assertThat(ManagementBindWarning.isLoopback("localhost")).isTrue();
        assertThat(ManagementBindWarning.isLoopback(" 127.0.0.1 ")).isTrue();
    }

    @Test
    void exposedOrUnrecognizedBindsWarn() {
        assertThat(ManagementBindWarning.isLoopback("0.0.0.0")).isFalse();
        assertThat(ManagementBindWarning.isLoopback("::")).isFalse();
        assertThat(ManagementBindWarning.isLoopback("192.168.1.10")).isFalse();
        assertThat(ManagementBindWarning.isLoopback("metrics.internal")).isFalse();
        assertThat(ManagementBindWarning.isLoopback("")).isFalse();
        assertThat(ManagementBindWarning.isLoopback(null)).isFalse();
    }
}
