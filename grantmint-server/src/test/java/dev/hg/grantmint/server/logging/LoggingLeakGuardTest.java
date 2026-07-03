package dev.hg.grantmint.server.logging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.issuance.IssuanceCommand;
import dev.hg.grantmint.server.issuance.IssuanceService;
import dev.hg.grantmint.server.issuance.IssuedLicense;
import dev.hg.grantmint.server.metrics.GrantmintMetrics;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.PolicyRepository;
import dev.hg.grantmint.server.signing.SigningKeyService;
import dev.hg.grantmint.server.validation.ValidationCache;
import dev.hg.grantmint.server.validation.ValidationService;
import dev.hg.grantmint.server.validation.ValidationSnapshot;
import dev.hg.grantmint.server.validation.ValidationSnapshotLoader;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

/**
 * The leakage contract for GRANTMINT-101: the issuance/validation log lines carry the safe,
 * public identifiers (keyId) an operator needs to correlate a request, and never the signed token
 * or holder PII — at any log level, in message text or an MDC value. See
 * docs/operations/MONITORING_LOGGING.md ("What NOT to log").
 *
 * <p>Drives {@link IssuanceService} and {@link ValidationService} exactly as {@code
 * IssuanceServiceTest}/{@code ValidationMetricsTest} do (mocked persistence, a real Ed25519 signer,
 * {@code new GrantmintMetrics(new SimpleMeterRegistry())}) with a {@link ListAppender} attached to
 * the root Logback logger so every log event either service emits is captured.
 */
@ExtendWith(MockitoExtension.class)
class LoggingLeakGuardTest {

    private static final String SIGNING_KEY_ID = "ed25519-2026-01";
    private static final UUID PRODUCT_ID = UUID.randomUUID();
    private static final UUID POLICY_ID = UUID.randomUUID();
    private static final Instant NOW = Instant.parse("2026-06-28T12:00:00Z");
    private static final String HOLDER_NAME = "Jane Doe";
    private static final String HOLDER_EMAIL = "jane@example.com";
    private static final String VALIDATION_KEY_ID = "K7QF-9M2T-4XR8";

    @Mock
    private PolicyRepository policies;

    @Mock
    private LicenseRepository licenses;

    @Mock
    private SigningKeyService signingKeys;

    @Mock
    private AuditService audit;

    private Logger rootLogger;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void attachAppender() {
        rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        appender = new ListAppender<>();
        appender.start();
        rootLogger.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        rootLogger.detachAppender(appender);
    }

    @Test
    void issuanceLogsTheKeyIdButNeverTheTokenOrHolderPii() {
        KeyPair pair = Ed25519Keys.generate(new SecureRandom());
        byte[] seed = Ed25519Keys.encodePrivateKey(pair.getPrivate());
        Ed25519Signer signer = Ed25519Signer.fromRawSeed(seed, SIGNING_KEY_ID);
        Clock fixed = Clock.fixed(NOW, ZoneOffset.UTC);
        IssuanceService service = new IssuanceService(
                policies, licenses, signingKeys, audit, fixed, new GrantmintMetrics(new SimpleMeterRegistry()));
        lenient().when(signingKeys.signerForProduct(PRODUCT_ID)).thenReturn(signer);
        lenient().when(licenses.existsByKeyId(anyString())).thenReturn(false);
        lenient().when(licenses.save(any(License.class))).thenAnswer(inv -> inv.getArgument(0));

        Product product = new Product();
        product.setId(PRODUCT_ID);
        product.setSlug("acme-notes");
        product.setActiveSigningKeyId(SIGNING_KEY_ID);
        Policy policy = new Policy();
        policy.setId(POLICY_ID);
        policy.setProduct(product);
        policy.setCode("pro-annual");
        policy.setName("Pro Annual");
        policy.setMaxSeats(2);
        policy.setDurationDays(365);
        policy.setEntitlements(new LinkedHashMap<>(Map.of("team_sync", true)));
        when(policies.findById(POLICY_ID)).thenReturn(Optional.of(policy));

        IssuanceCommand command = new IssuanceCommand(
                PRODUCT_ID, POLICY_ID, HOLDER_NAME, HOLDER_EMAIL, null, null, null, "key-1", "203.0.113.7");

        IssuedLicense issued = service.issue(command);

        assertThat(events())
                .anySatisfy(event -> assertThat(event.getFormattedMessage()).contains("license issued"));
        assertThat(mdcValues()).anySatisfy(value -> assertThat(value).isEqualTo(issued.keyId()));
        assertNoLeak(issued.token());
    }

    @Test
    void validationLogsTheOutcomeWithoutLeakingSensitiveData() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        ValidationSnapshotLoader loader = new ValidationSnapshotLoader(null, null, Clock.systemUTC()) {
            @Override
            public ValidationSnapshot load(String keyId) {
                return new ValidationSnapshot(
                        PRODUCT_ID, "acme-notes", LicenseStatus.ACTIVE, true, null, null, 2, Map.of("team_sync", true));
            }
        };
        ValidationService service = new ValidationService(
                new ValidationCache(Duration.ofMinutes(5), 100),
                loader,
                Clock.systemUTC(),
                new GrantmintMetrics(registry));

        service.validate(VALIDATION_KEY_ID, PRODUCT_ID, null);

        assertThat(events())
                .anySatisfy(event -> assertThat(event.getFormattedMessage()).contains("online validation"));
        assertThat(mdcValues()).anySatisfy(value -> assertThat(value).isEqualTo(VALIDATION_KEY_ID));
        assertNoLeak(null);
    }

    private java.util.List<ILoggingEvent> events() {
        return appender.list;
    }

    private java.util.List<String> mdcValues() {
        return events().stream()
                .flatMap(event -> event.getMDCPropertyMap().values().stream())
                .toList();
    }

    /** No captured message or MDC value may contain the signed token, the holder name, or the holder email. */
    private void assertNoLeak(String signedToken) {
        for (ILoggingEvent event : events()) {
            String message = event.getFormattedMessage();
            assertThat(message).doesNotContain(HOLDER_NAME);
            assertThat(message).doesNotContain(HOLDER_EMAIL);
            if (signedToken != null) {
                assertThat(message).doesNotContain(signedToken);
            }
            for (String value : event.getMDCPropertyMap().values()) {
                assertThat(value).doesNotContain(HOLDER_NAME);
                assertThat(value).doesNotContain(HOLDER_EMAIL);
                if (signedToken != null) {
                    assertThat(value).doesNotContain(signedToken);
                }
            }
        }
    }
}
