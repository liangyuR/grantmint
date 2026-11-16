package dev.hg.grantmint.server.api;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.hg.grantmint.server.offline.OfflineLicenseException;
import dev.hg.grantmint.server.offline.OfflineLicenseService;
import dev.hg.grantmint.server.security.AdminPrincipal;
import dev.hg.grantmint.server.validation.ClientIpResolver;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OfflineLicenseController {
    private final OfflineLicenseService service;
    private final ClientIpResolver clientIp;
    private final Cache<String, AtomicInteger> calls = Caffeine.newBuilder()
            .maximumSize(10_000)
            .expireAfterWrite(Duration.ofMinutes(1))
            .build();

    public OfflineLicenseController(OfflineLicenseService service, ClientIpResolver clientIp) {
        this.service = service;
        this.clientIp = clientIp;
    }

    @PostMapping("/admin/v2/licenses")
    @ResponseStatus(HttpStatus.CREATED)
    public OfflineLicenseService.Created create(
            @RequestBody OfflineLicenseService.CreateRequest request, @AuthenticationPrincipal AdminPrincipal admin) {
        return service.create(request, admin.username());
    }

    @PostMapping("/v2/licenses/challenges")
    public OfflineLicenseService.ChallengeResponse challenge(
            @RequestBody OfflineLicenseService.ChallengeRequest request, HttpServletRequest http) {
        rateLimit(http);
        return service.challenge(request);
    }

    @PostMapping("/v2/licenses/activate")
    public OfflineLicenseService.Activated activate(
            @RequestBody OfflineLicenseService.ActivateRequest request, HttpServletRequest http) {
        rateLimit(http);
        return service.activate(request);
    }

    private void rateLimit(HttpServletRequest request) {
        if (calls.get(clientIp.resolve(request), ignored -> new AtomicInteger()).incrementAndGet() > 60)
            throw new OfflineLicenseException(429, "activation_rate_limited");
    }
}
