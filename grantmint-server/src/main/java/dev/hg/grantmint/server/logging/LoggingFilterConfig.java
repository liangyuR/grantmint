package dev.hg.grantmint.server.logging;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers {@link MdcFilter} with just-lower-than-security precedence ({@link
 * SecurityProperties#DEFAULT_FILTER_ORDER}{@code + 1}), so it runs immediately <em>after</em> the
 * Spring Security filter chain and before the {@code DispatcherServlet} — the {@link
 * org.springframework.security.core.context.SecurityContext} is already populated by whichever of
 * the three auth schemes (docs/features/ADMIN_AND_API_AUTH.md) matched the request, so {@code actor}
 * resolution never has to reach into a filter still mid-authentication. See
 * docs/operations/MONITORING_LOGGING.md ("MDC fields").
 */
@Configuration
public class LoggingFilterConfig {

    @Bean
    public FilterRegistrationBean<MdcFilter> mdcFilter() {
        FilterRegistrationBean<MdcFilter> registration = new FilterRegistrationBean<>(new MdcFilter());
        registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER + 1);
        registration.addUrlPatterns("/*");
        return registration;
    }
}
