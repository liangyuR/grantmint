package dev.hg.grantmint.server.issuance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.keyid.KeyId;
import dev.hg.grantmint.core.time.Clock;
import dev.hg.grantmint.core.token.LicenseVerifier;
import dev.hg.grantmint.core.token.TokenPayload;
import dev.hg.grantmint.core.token.VerificationResult;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.PolicyRepository;
import dev.hg.grantmint.server.signing.SigningKeyService;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

/**
 * Issuance mechanics with mocked persistence and a real Ed25519 signer: the minted token verifies
 * offline against the signing key, carries the policy's claims and entitlements, and the persisted
 * license snapshots the policy. Also covers the cross-product guard, expiry computation, and
 * overrides. The exhaustive "any valid policy" property lives in {@code IssuancePropertyTest}.
 */
@ExtendWith(MockitoExtension.class)
class IssuanceServiceTest {

    private static final String SIGNING_KEY_ID = "ed25519-2026-01";
    private static final UUID PRODUCT_ID = UUID.randomUUID();
    private static final UUID POLICY_ID = UUID.randomUUID();
    private static final Instant NOW = Instant.parse("2026-06-28T12:00:00Z");

    @Mock
    private PolicyRepository policies;

    @Mock
    private LicenseRepository licenses;

    @Mock
    private SigningKeyService signingKeys;

    @Mock
    private AuditService audit;

    private PublicKey publicKey;
    private IssuanceService service;

    @BeforeEach
    void setUp() {
        KeyPair pair = Ed25519Keys.generate(new SecureRandom());
        publicKey = pair.getPublic();
        byte[] seed = Ed25519Keys.encodePrivateKey(pair.getPrivate());
        Ed25519Signer signer = Ed25519Signer.fromRawSeed(seed, SIGNING_KEY_ID);
        java.time.Clock fixed = java.time.Clock.fixed(NOW, ZoneOffset.UTC);
        service = new IssuanceService(policies, licenses, signingKeys, audit, fixed);
        // Lenient-by-default stubs are configured per test to avoid unnecessary-stubbing failures.
        org.mockito.Mockito.lenient()
                .when(signingKeys.signerForProduct(PRODUCT_ID))
                .thenReturn(signer);
        org.mockito.Mockito.lenient().when(licenses.existsByKeyId(anyString())).thenReturn(false);
        org.mockito.Mockito.lenient().when(licenses.save(any(License.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void mintsTokenThatVerifiesOfflineAndCarriesPolicyClaims() {
        Policy policy = policy(365, 2, Map.of("team_sync", true, "max_devices", 5));
        when(policies.findById(POLICY_ID)).thenReturn(Optional.of(policy));

        IssuedLicense issued = service.issue(command(null, null));

        assertThat(issued.status()).isEqualTo(LicenseStatus.ACTIVE);
        assertThat(KeyId.isValid(issued.keyId())).isTrue();
        assertThat(issued.expiresAt()).isEqualTo(NOW.atOffset(ZoneOffset.UTC).plusDays(365));

        VerificationResult result = LicenseVerifier.verifyAt(issued.token(), publicKey, Clock.fixed(NOW));
        assertThat(result.isValid()).isTrue();
        TokenPayload payload = result.payload();
        assertThat(payload.kid()).isEqualTo(issued.keyId());
        assertThat(payload.prd()).isEqualTo("acme-notes");
        assertThat(payload.pol()).isEqualTo("pro-annual");
        assertThat(payload.holder().email()).isEqualTo("jane@example.com");
        assertThat(payload.iat()).isEqualTo(NOW.getEpochSecond());
        assertThat(payload.exp()).isEqualTo(issued.expiresAt().toEpochSecond());
        assertThat(payload.seat()).isEqualTo(2);
        assertThat(payload.entitlements().isEnabled("team_sync")).isTrue();
        assertThat(payload.entitlements().limit("max_devices", -1)).isEqualTo(5);
    }

    @Test
    void persistsLicenseWithSnapshotAndEmbeddedLid() {
        Policy policy = policy(365, 2, Map.of("team_sync", true));
        when(policies.findById(POLICY_ID)).thenReturn(Optional.of(policy));

        IssuedLicense issued = service.issue(command(null, null));

        ArgumentCaptor<License> captor = ArgumentCaptor.forClass(License.class);
        verify(licenses).save(captor.capture());
        License saved = captor.getValue();
        assertThat(saved.getStatus()).isEqualTo(LicenseStatus.ACTIVE);
        assertThat(saved.getKeyId()).isEqualTo(issued.keyId());
        assertThat(saved.getSignedToken()).isEqualTo(issued.token());
        assertThat(saved.getSigningKeyId()).isEqualTo(SIGNING_KEY_ID);
        assertThat(saved.getMaxSeats()).isEqualTo(2);
        assertThat(saved.getEntitlements()).containsEntry("team_sync", true);
        // The snapshot is a copy — mutating the policy afterwards must not touch the license.
        assertThat(saved.getEntitlements()).isNotSameAs(policy.getEntitlements());

        VerificationResult result = LicenseVerifier.verifyAt(issued.token(), publicKey, Clock.fixed(NOW));
        assertThat(result.payload().lid()).isEqualTo(saved.getId().toString());

        verify(audit)
                .record(
                        anyString(),
                        any(),
                        org.mockito.ArgumentMatchers.eq("license.issued"),
                        anyString(),
                        anyString(),
                        any(),
                        org.mockito.ArgumentMatchers.any());
    }

    @Test
    void perpetualWhenNoDurationAndNoOverride() {
        Policy policy = policy(null, 1, Map.of());
        when(policies.findById(POLICY_ID)).thenReturn(Optional.of(policy));

        IssuedLicense issued = service.issue(command(null, null));

        assertThat(issued.expiresAt()).isNull();
        VerificationResult result = LicenseVerifier.verifyAt(issued.token(), publicKey, Clock.fixed(NOW));
        assertThat(result.payload().exp()).isNull();
    }

    @Test
    void expiryOverrideWins() {
        Policy policy = policy(30, 1, Map.of());
        when(policies.findById(POLICY_ID)).thenReturn(Optional.of(policy));
        var override = Instant.parse("2030-01-01T00:00:00Z").atOffset(ZoneOffset.UTC);

        IssuedLicense issued = service.issue(command(override, null));

        assertThat(issued.expiresAt()).isEqualTo(override);
    }

    @Test
    void seatOverrideWins() {
        Policy policy = policy(30, 1, Map.of());
        when(policies.findById(POLICY_ID)).thenReturn(Optional.of(policy));

        IssuedLicense issued = service.issue(command(null, 7));

        VerificationResult result = LicenseVerifier.verifyAt(issued.token(), publicKey, Clock.fixed(NOW));
        assertThat(result.payload().seat()).isEqualTo(7);
    }

    @Test
    void deniesCrossProductIssuance() {
        Policy policy = policy(30, 1, Map.of());
        policy.getProduct().setId(UUID.randomUUID()); // belongs to a different product
        when(policies.findById(POLICY_ID)).thenReturn(Optional.of(policy));

        assertThatThrownBy(() -> service.issue(command(null, null))).isInstanceOf(AccessDeniedException.class);
        verify(licenses, never()).save(any());
    }

    @Test
    void failsWhenPolicyMissing() {
        when(policies.findById(POLICY_ID)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.issue(command(null, null))).isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void rejectsMissingHolder() {
        assertThatThrownBy(() -> service.issue(new IssuanceCommand(
                        PRODUCT_ID, POLICY_ID, " ", "jane@example.com", null, null, null, "key-1", null)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private Policy policy(Integer durationDays, int maxSeats, Map<String, Object> entitlements) {
        Product product = new Product();
        product.setId(PRODUCT_ID);
        product.setSlug("acme-notes");
        product.setActiveSigningKeyId(SIGNING_KEY_ID);
        Policy policy = new Policy();
        policy.setId(POLICY_ID);
        policy.setProduct(product);
        policy.setCode("pro-annual");
        policy.setName("Pro Annual");
        policy.setMaxSeats(maxSeats);
        policy.setDurationDays(durationDays);
        policy.setEntitlements(new LinkedHashMap<>(entitlements));
        return policy;
    }

    private IssuanceCommand command(java.time.OffsetDateTime expiresOverride, Integer seatOverride) {
        return new IssuanceCommand(
                PRODUCT_ID,
                POLICY_ID,
                "Jane Doe",
                "jane@example.com",
                expiresOverride,
                seatOverride,
                null,
                "key-1",
                "203.0.113.7");
    }
}
