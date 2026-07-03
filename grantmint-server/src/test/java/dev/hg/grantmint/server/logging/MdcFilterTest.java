package dev.hg.grantmint.server.logging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.servlet.FilterChain;
import java.util.UUID;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * {@link MdcFilter}'s contract: {@code requestId} comes from the {@code X-Request-Id} header when
 * present, is generated otherwise, and MDC is always empty once the filter returns — including when
 * the downstream chain throws (thread pools reuse threads). See
 * docs/operations/MONITORING_LOGGING.md ("MDC fields").
 */
class MdcFilterTest {

    private static final Pattern UUID_PATTERN =
            Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private final MdcFilter filter = new MdcFilter();

    @AfterEach
    void resetGlobalState() {
        SecurityContextHolder.clearContext();
        MDC.clear();
    }

    @Test
    void usesRequestIdHeaderWhenPresent() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(MdcFilter.REQUEST_ID_HEADER, "caller-supplied-id");
        MockHttpServletResponse response = new MockHttpServletResponse();
        String[] seenDuringChain = new String[1];
        FilterChain chain = (req, res) -> seenDuringChain[0] = MDC.get("requestId");

        filter.doFilter(request, response, chain);

        assertThat(seenDuringChain[0]).isEqualTo("caller-supplied-id");
    }

    @Test
    void generatesARequestIdWhenTheHeaderIsAbsent() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String[] seenDuringChain = new String[1];
        FilterChain chain = (req, res) -> seenDuringChain[0] = MDC.get("requestId");

        filter.doFilter(request, response, chain);

        assertThat(seenDuringChain[0]).isNotBlank();
        assertThat(UUID_PATTERN.matcher(seenDuringChain[0]).matches()).isTrue();
        assertThat(UUID.fromString(seenDuringChain[0])).isNotNull();
    }

    @Test
    void generatesARequestIdWhenTheHeaderIsBlank() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(MdcFilter.REQUEST_ID_HEADER, "   ");
        MockHttpServletResponse response = new MockHttpServletResponse();
        String[] seenDuringChain = new String[1];
        FilterChain chain = (req, res) -> seenDuringChain[0] = MDC.get("requestId");

        filter.doFilter(request, response, chain);

        assertThat(UUID_PATTERN.matcher(seenDuringChain[0]).matches()).isTrue();
    }

    @Test
    void mdcIsEmptyAfterTheFilterReturns() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> {
            /* no-op downstream */
        };

        filter.doFilter(request, response, chain);

        assertThat(isMdcEmpty()).isTrue();
    }

    @Test
    void mdcIsClearedEvenWhenTheChainThrows() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> {
            throw new IllegalStateException("downstream failure");
        };

        assertThatThrownBy(() -> filter.doFilter(request, response, chain)).isInstanceOf(IllegalStateException.class);

        assertThat(isMdcEmpty()).isTrue();
    }

    private static boolean isMdcEmpty() {
        var context = MDC.getCopyOfContextMap();
        return context == null || context.isEmpty();
    }
}
