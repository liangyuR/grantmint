package dev.hg.grantmint.server.validation;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Unit tests for {@link ClientIpResolver} — the proxy-aware client-IP extraction backing the per-IP
 * rate limit. The security-critical invariant is that {@code X-Forwarded-For} is honoured only when
 * the socket peer is a configured trusted proxy; a direct (untrusted) client cannot spoof its IP.
 */
class ClientIpResolverTest {

    @Test
    void withoutTrustedProxiesAlwaysUsesPeerAndIgnoresForwardedHeader() {
        ClientIpResolver resolver = new ClientIpResolver(List.of());
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("198.51.100.9");
        request.addHeader("X-Forwarded-For", "1.2.3.4"); // spoof attempt — must be ignored

        assertThat(resolver.resolve(request)).isEqualTo("198.51.100.9");
    }

    @Test
    void untrustedPeerForwardedHeaderIsIgnored() {
        ClientIpResolver resolver = new ClientIpResolver(List.of("10.0.0.0/8"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.50"); // not in 10.0.0.0/8 → not a trusted proxy
        request.addHeader("X-Forwarded-For", "1.2.3.4");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.50");
    }

    @Test
    void trustedProxyYieldsForwardedClient() {
        ClientIpResolver resolver = new ClientIpResolver(List.of("10.0.0.0/8"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.1.2.3"); // trusted proxy
        request.addHeader("X-Forwarded-For", "203.0.113.7");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.7");
    }

    @Test
    void walksBackThroughAChainOfTrustedProxies() {
        // client → edge proxy (10.x) → internal proxy (10.x): the rightmost non-trusted hop is the client.
        ClientIpResolver resolver = new ClientIpResolver(List.of("10.0.0.0/8"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.9");
        request.addHeader("X-Forwarded-For", "203.0.113.7, 10.9.9.9");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.7");
    }

    @Test
    void trustedProxyWithoutForwardedHeaderFallsBackToPeer() {
        ClientIpResolver resolver = new ClientIpResolver(List.of("10.0.0.0/8"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.1.2.3");

        assertThat(resolver.resolve(request)).isEqualTo("10.1.2.3");
    }

    @Test
    void bareIpTrustedProxyMatchesAsHostRoute() {
        ClientIpResolver resolver = new ClientIpResolver(List.of("192.168.1.5"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.5");
        request.addHeader("X-Forwarded-For", "203.0.113.7");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.7");
    }

    @Test
    void nonLiteralForwardedHopIsSkipped() {
        // A hostname in X-Forwarded-For must never be DNS-resolved; it is treated as untrusted/unusable
        // and skipped, so the resolver keeps walking (here, to the only valid client literal).
        ClientIpResolver resolver = new ClientIpResolver(List.of("10.0.0.0/8"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("X-Forwarded-For", "203.0.113.7, evil.example.com");

        // evil.example.com is not a trusted proxy (not even a literal) → returned as the client hop.
        assertThat(resolver.resolve(request)).isEqualTo("evil.example.com");
    }

    @Test
    void ipv6TrustedProxyAndForwardedClient() {
        ClientIpResolver resolver = new ClientIpResolver(List.of("2001:db8::/32"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("2001:db8::1");
        request.addHeader("X-Forwarded-For", "2001:db8:abcd::42, 198.51.100.7");

        // Rightmost non-trusted hop is the IPv4 client (not in the v6 trusted block).
        assertThat(resolver.resolve(request)).isEqualTo("198.51.100.7");
    }
}
