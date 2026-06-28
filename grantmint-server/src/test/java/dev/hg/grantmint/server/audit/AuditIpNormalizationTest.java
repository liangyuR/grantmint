package dev.hg.grantmint.server.audit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AuditService#normalizeIpOrNull(String)} — the DNS-free guard that keeps a
 * malformed request IP from defeating an audit write against the PostgreSQL {@code inet} column.
 */
class AuditIpNormalizationTest {

    @Test
    void keepsValidIpv4() {
        assertThat(AuditService.normalizeIpOrNull("192.168.1.1")).isEqualTo("192.168.1.1");
        assertThat(AuditService.normalizeIpOrNull("0.0.0.0")).isEqualTo("0.0.0.0");
        assertThat(AuditService.normalizeIpOrNull("255.255.255.255")).isEqualTo("255.255.255.255");
    }

    @Test
    void keepsValidIpv6() {
        assertThat(AuditService.normalizeIpOrNull("::1")).isEqualTo("::1");
        assertThat(AuditService.normalizeIpOrNull("2001:db8::ff00:42:8329")).isEqualTo("2001:db8::ff00:42:8329");
    }

    @Test
    void trimsSurroundingWhitespace() {
        assertThat(AuditService.normalizeIpOrNull("  10.0.0.5  ")).isEqualTo("10.0.0.5");
    }

    @Test
    void dropsNullAndBlankToNull() {
        assertThat(AuditService.normalizeIpOrNull(null)).isNull();
        assertThat(AuditService.normalizeIpOrNull("")).isNull();
        assertThat(AuditService.normalizeIpOrNull("   ")).isNull();
    }

    @Test
    void dropsMalformedToNull() {
        assertThat(AuditService.normalizeIpOrNull("not-an-ip")).isNull();
        assertThat(AuditService.normalizeIpOrNull("999.1.1.1")).isNull();
        assertThat(AuditService.normalizeIpOrNull("1.2.3")).isNull();
        assertThat(AuditService.normalizeIpOrNull("1.2.3.4.5")).isNull();
        assertThat(AuditService.normalizeIpOrNull("12:34")).isNull();
        assertThat(AuditService.normalizeIpOrNull("example.com")).isNull();
    }
}
