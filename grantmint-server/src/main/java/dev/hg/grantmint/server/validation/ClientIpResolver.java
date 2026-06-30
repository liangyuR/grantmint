package dev.hg.grantmint.server.validation;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Resolves the real client IP for per-IP rate limiting when the server sits behind a reverse proxy.
 *
 * <p>{@link HttpServletRequest#getRemoteAddr()} returns the immediate TCP peer — which, behind a
 * proxy or load balancer, is the proxy itself. Keying the per-IP rate-limit bucket on that would make
 * the limit effectively per-proxy (one shared bucket for every real client), defeating it. This
 * resolver consults {@code X-Forwarded-For}, but <strong>only</strong> when the immediate peer is a
 * configured trusted proxy — otherwise the header is attacker-controlled and is ignored, so a direct
 * client cannot spoof its source IP to dodge or frame another address.
 *
 * <p>When trusted, the chain is walked from the right (closest hop) and the first address that is not
 * itself a trusted proxy is taken as the client — correct for a stack of our own proxies. With no
 * trusted proxies configured (the default), the socket peer is always used: safe by default, opt in
 * to forwarded headers only once the proxy topology is known. Configure via
 * {@code grantmint.validation.rate-limit.trusted-proxies} (a list of CIDRs or bare IPs).
 */
public final class ClientIpResolver {

    private static final String FORWARDED_FOR = "X-Forwarded-For";

    private final List<Cidr> trustedProxies;

    public ClientIpResolver(List<String> trustedProxyCidrs) {
        List<Cidr> parsed = new ArrayList<>();
        if (trustedProxyCidrs != null) {
            for (String entry : trustedProxyCidrs) {
                if (entry != null && !entry.isBlank()) {
                    parsed.add(Cidr.parse(entry.trim()));
                }
            }
        }
        this.trustedProxies = List.copyOf(parsed);
    }

    /** Resolve the client IP to use for rate limiting. Never returns null in practice (peer addr). */
    public String resolve(HttpServletRequest request) {
        String peer = request.getRemoteAddr();
        // No proxy configured, or the peer is not a trusted proxy: trust only the socket peer; any
        // X-Forwarded-For it sent is unverified and deliberately ignored.
        if (trustedProxies.isEmpty() || !isTrusted(peer)) {
            return peer;
        }
        String forwarded = request.getHeader(FORWARDED_FOR);
        if (forwarded == null || forwarded.isBlank()) {
            return peer;
        }
        String[] hops = forwarded.split(",");
        for (int i = hops.length - 1; i >= 0; i--) {
            String hop = hops[i].trim();
            if (hop.isEmpty()) {
                continue;
            }
            if (!isTrusted(hop)) {
                return hop;
            }
        }
        // Every hop was one of our own trusted proxies (or unparseable): fall back to the peer.
        return peer;
    }

    private boolean isTrusted(String ip) {
        InetAddress addr = parseLiteral(ip);
        if (addr == null) {
            return false;
        }
        for (Cidr cidr : trustedProxies) {
            if (cidr.contains(addr)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Parse an IP <em>literal</em> only — never a hostname (which would trigger a DNS lookup on
     * attacker-controlled header content). Returns null for anything that is not a v4/v6 literal.
     */
    private static InetAddress parseLiteral(String ip) {
        if (!isIpLiteral(ip)) {
            return null;
        }
        try {
            return InetAddress.getByName(ip);
        } catch (UnknownHostException notALiteral) {
            return null;
        }
    }

    private static boolean isIpLiteral(String s) {
        boolean hasColon = s.indexOf(':') >= 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= '0' && c <= '9')
                    || c == '.'
                    || (hasColon && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':'));
            if (!ok) {
                return false;
            }
        }
        return !s.isEmpty();
    }

    /** A parsed CIDR block (or a bare IP, treated as a host route). */
    private record Cidr(byte[] network, int prefixBits) {

        static Cidr parse(String cidr) {
            int slash = cidr.indexOf('/');
            String ip = slash < 0 ? cidr : cidr.substring(0, slash);
            InetAddress base;
            try {
                base = InetAddress.getByName(ip);
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("Invalid trusted-proxy address: " + cidr, e);
            }
            byte[] network = base.getAddress();
            int maxBits = network.length * 8;
            int prefix;
            if (slash < 0) {
                prefix = maxBits;
            } else {
                try {
                    prefix = Integer.parseInt(cidr.substring(slash + 1));
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid trusted-proxy CIDR prefix: " + cidr, e);
                }
            }
            if (prefix < 0 || prefix > maxBits) {
                throw new IllegalArgumentException(
                        String.format(Locale.ROOT, "Trusted-proxy CIDR prefix out of range for %s: %d", cidr, prefix));
            }
            return new Cidr(network, prefix);
        }

        boolean contains(InetAddress addr) {
            byte[] a = addr.getAddress();
            if (a.length != network.length) {
                return false; // v4 cannot match a v6 block and vice-versa
            }
            int fullBytes = prefixBits / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (a[i] != network[i]) {
                    return false;
                }
            }
            int remainingBits = prefixBits % 8;
            if (remainingBits > 0) {
                int mask = (0xFF << (8 - remainingBits)) & 0xFF;
                return (a[fullBytes] & mask) == (network[fullBytes] & mask);
            }
            return true;
        }
    }
}
