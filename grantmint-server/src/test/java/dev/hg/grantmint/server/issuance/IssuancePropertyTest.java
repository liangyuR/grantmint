package dev.hg.grantmint.server.issuance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.entitlement.EntitlementSet;
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
import java.util.Optional;
import java.util.UUID;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.LongRange;
import net.jqwik.api.constraints.StringLength;

/**
 * M4 property: <em>every</em> license issued from any valid policy produces a token that verifies
 * offline against the signing key's public half and carries exactly the policy's entitlements,
 * expiry, and seat count. This is the issuance-layer counterpart of the core's "any issued token
 * verifies" property — here we vary the policy, not the raw payload. See docs/testing/TESTING.md.
 */
class IssuancePropertyTest {

    private static final SecureRandom RNG = new SecureRandom();
    private static final String SIGNING_KEY_ID = "K1";
    private static final UUID PRODUCT_ID = UUID.randomUUID();
    private static final UUID POLICY_ID = UUID.randomUUID();
    private static final Instant NOW = Instant.parse("2026-06-28T12:00:00Z");

    @Property(tries = 1000)
    void anyValidPolicyMintsAVerifiableTokenCarryingItsTerms(
            @ForAll @IntRange(min = 0, max = 3650) int durationDaysOrPerpetual,
            @ForAll @IntRange(min = 0, max = 365) int gracePeriodDays,
            @ForAll @IntRange(min = 1, max = 100_000) int maxSeats,
            @ForAll boolean flagValue,
            @ForAll @LongRange(min = -1, max = 1_000_000_000L) long limitValue,
            @ForAll @AlphaChars @StringLength(min = 1, max = 10) String tierValue,
            @ForAll @AlphaChars @StringLength(min = 1, max = 8) String emailLocalPart) {

        KeyPair keyPair = Ed25519Keys.generate(RNG);
        PublicKey publicKey = keyPair.getPublic();
        Ed25519Signer signer = new Ed25519Signer(keyPair.getPrivate(), SIGNING_KEY_ID);

        PolicyRepository policies = mock(PolicyRepository.class);
        LicenseRepository licenses = mock(LicenseRepository.class);
        AuditService audit = mock(AuditService.class);
        SigningKeyService signingKeys = new SigningKeyService(null, null, null) {
            @Override
            public Ed25519Signer signerForProduct(UUID productId) {
                return signer;
            }
        };
        IssuanceService service = new IssuanceService(
                policies,
                licenses,
                signingKeys,
                audit,
                java.time.Clock.fixed(NOW, ZoneOffset.UTC),
                new dev.hg.grantmint.server.metrics.GrantmintMetrics(
                        new io.micrometer.core.instrument.simple.SimpleMeterRegistry()));

        Integer durationDays = durationDaysOrPerpetual == 0 ? null : durationDaysOrPerpetual;
        Map<String, Object> entitlements = new LinkedHashMap<>();
        entitlements.put("team_sync", flagValue);
        entitlements.put("max_devices", limitValue);
        entitlements.put("tier", tierValue);
        Policy policy = policy(durationDays, maxSeats, entitlements);
        policy.setGracePeriodDays(gracePeriodDays);

        when(policies.findById(POLICY_ID)).thenReturn(Optional.of(policy));
        when(licenses.existsByKeyId(anyString())).thenReturn(false);
        when(licenses.save(any(License.class))).thenAnswer(invocation -> invocation.getArgument(0));

        String email = emailLocalPart + "@example.com";
        IssuedLicense issued = service.issue(
                new IssuanceCommand(PRODUCT_ID, POLICY_ID, "Holder", email, null, null, null, "key-1", null));

        VerificationResult result = LicenseVerifier.verifyAt(issued.token(), publicKey, Clock.fixed(NOW));
        assertThat(result.isValid()).as("issued token must verify offline").isTrue();

        TokenPayload payload = result.payload();
        assertThat(issued.status()).isEqualTo(LicenseStatus.ACTIVE);
        assertThat(payload.kid()).isEqualTo(issued.keyId());
        assertThat(payload.prd()).isEqualTo("acme-notes");
        assertThat(payload.pol()).isEqualTo("pro-annual");
        assertThat(payload.holder().email()).isEqualTo(email);
        assertThat(payload.seat()).isEqualTo(maxSeats);

        // Entitlements carried exactly (decode round-trips through the token's ent claim).
        assertThat(payload.entitlements()).isEqualTo(EntitlementSet.decode(entitlements));

        // Expiry: perpetual stays null everywhere. Otherwise the database expiry is strict
        // (NOW + duration — where online enforcement flips) while the token's cryptographic exp
        // trails it by the policy's grace period, so the offline artefact keeps verifying through
        // the grace window and fails on its own past it (LICENSE_LIFECYCLE.md, expiry + grace).
        if (durationDays == null) {
            assertThat(payload.exp()).isNull();
            assertThat(issued.expiresAt()).isNull();
        } else {
            long expectedDbExpiry =
                    NOW.atOffset(ZoneOffset.UTC).plusDays(durationDays).toEpochSecond();
            long expectedTokenExp = NOW.atOffset(ZoneOffset.UTC)
                    .plusDays(durationDays)
                    .plusDays(gracePeriodDays)
                    .toEpochSecond();
            assertThat(issued.expiresAt().toEpochSecond()).isEqualTo(expectedDbExpiry);
            assertThat(payload.exp()).isEqualTo(expectedTokenExp);

            // Offline behaviour across the window: verifies just inside the grace window,
            // cryptographically dead the second the (grace-extended) exp is reached.
            assertThat(LicenseVerifier.verifyAt(
                                    issued.token(), publicKey, Clock.fixed(Instant.ofEpochSecond(expectedTokenExp - 1)))
                            .isValid())
                    .as("token must verify inside the grace window")
                    .isTrue();
            assertThat(LicenseVerifier.verifyAt(
                                    issued.token(), publicKey, Clock.fixed(Instant.ofEpochSecond(expectedTokenExp)))
                            .isValid())
                    .as("token must fail once the grace-extended exp is reached")
                    .isFalse();
        }
    }

    private static Policy policy(Integer durationDays, int maxSeats, Map<String, Object> entitlements) {
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
}
