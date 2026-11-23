package dev.hg.grantmint.server.offline;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.grantmint.core.codec.Base64Url;
import dev.hg.grantmint.core.crypto.CryptoException;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.crypto.Ed25519Verifier;
import dev.hg.grantmint.core.keyid.KeyId;
import dev.hg.grantmint.core.token.OfflineDeviceTokens;
import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.domain.License;
import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.domain.MachineActivation;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.repo.LicenseRepository;
import dev.hg.grantmint.server.repo.MachineActivationRepository;
import dev.hg.grantmint.server.repo.PolicyRepository;
import dev.hg.grantmint.server.security.Secrets;
import dev.hg.grantmint.server.signing.SigningKeyService;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OfflineLicenseService {
    private final LicenseRepository licenses;
    private final PolicyRepository policies;
    private final MachineActivationRepository activations;
    private final SigningKeyService keys;
    private final JdbcTemplate jdbc;
    private final ObjectMapper json;
    private final AuditService audit;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public OfflineLicenseService(
            LicenseRepository licenses,
            PolicyRepository policies,
            MachineActivationRepository activations,
            SigningKeyService keys,
            JdbcTemplate jdbc,
            ObjectMapper json,
            AuditService audit,
            Clock clock) {
        this.licenses = licenses;
        this.policies = policies;
        this.activations = activations;
        this.keys = keys;
        this.jdbc = jdbc;
        this.json = json;
        this.audit = audit;
        this.clock = clock;
    }

    public record Holder(String name, String email) {}

    public record CreateRequest(UUID productId, UUID policyId, Holder holder, OffsetDateTime expiresAt) {}

    public record Created(
            UUID licenseId,
            String keyId,
            String activationSecret,
            String mode,
            String status,
            OffsetDateTime expiresAt) {}

    public record ChallengeRequest(
            UUID productId,
            UUID licenseId,
            String activationSecret,
            String devicePublicKey,
            String fingerprintHash,
            int fingerprintVersion) {}

    public record ChallengeResponse(UUID challengeId, String nonce, String message, OffsetDateTime expiresAt) {}

    public record ActivateRequest(
            UUID productId, UUID licenseId, UUID challengeId, String signature, String idempotencyKey) {}

    public record Activated(
            UUID licenseId,
            String keyId,
            String token,
            int revision,
            int bindingVersion,
            long serverTime,
            String timeReceipt) {}

    private record Challenge(
            UUID id,
            String nonce,
            String devicePublicKey,
            String fingerprintHash,
            int fingerprintVersion,
            OffsetDateTime expiresAt,
            String idempotencyKey,
            String signature,
            String response) {}

    @Transactional
    public Created create(CreateRequest request, String actor) {
        if (request.productId() == null
                || request.policyId() == null
                || request.holder() == null
                || request.holder().name() == null
                || request.holder().name().isBlank()
                || request.holder().email() == null
                || request.holder().email().isBlank()
                || request.expiresAt() == null
                || !request.expiresAt().withNano(0).isAfter(now())) {
            throw new OfflineLicenseException(400, "invalid_offline_contract");
        }
        Policy policy = policies.findById(request.policyId())
                .filter(p -> p.getProduct().getId().equals(request.productId()))
                .orElseThrow(() -> new OfflineLicenseException(404, "product_policy_not_found"));
        String secret = Secrets.randomTokenHex();
        License license = new License();
        license.setProduct(policy.getProduct());
        license.setPolicy(policy);
        license.setMode("offline_device_v2");
        license.setStatus(LicenseStatus.CREATED);
        license.setKeyId(KeyId.generate(random));
        license.setActivationSecretHash(Secrets.sha256Hex(secret));
        license.setMaxSeats(1);
        license.setHolderName(request.holder().name());
        license.setHolderEmail(request.holder().email());
        license.setExpiresAt(request.expiresAt().withNano(0));
        license.setEntitlements(new LinkedHashMap<>(policy.getEntitlements()));
        license.setConstraints(new LinkedHashMap<>(policy.getConstraints()));
        licenses.saveAndFlush(license);
        audit.record(
                actor,
                AuditActorType.ADMIN,
                "offline_license.created",
                "license",
                license.getId().toString(),
                Map.of("product_id", request.productId().toString()));
        return new Created(
                license.getId(), license.getKeyId(), secret, license.getMode(), "created", license.getExpiresAt());
    }

    @Transactional
    public ChallengeResponse challenge(ChallengeRequest request) {
        validateDevice(request.devicePublicKey(), request.fingerprintHash(), request.fingerprintVersion());
        License license = locked(request.licenseId(), request.productId());
        if (request.activationSecret() == null
                || request.activationSecret().length() != 64
                || !Secrets.constantTimeEqualsHex(
                        license.getActivationSecretHash(), Secrets.sha256Hex(request.activationSecret()))) {
            throw new OfflineLicenseException(401, "invalid_activation_credentials");
        }
        validContract(license);
        checkBinding(license, request.devicePublicKey(), request.fingerprintHash(), request.fingerprintVersion());
        jdbc.update(
                "delete from offline_activation_challenges where license_id = ? and expires_at < ? and response_json is null",
                license.getId(),
                now());
        Integer count = jdbc.queryForObject(
                "select count(*) from offline_activation_challenges where license_id = ?",
                Integer.class,
                license.getId());
        if (count != null && count >= 64) throw new OfflineLicenseException(429, "challenge_limit");
        UUID id = UUID.randomUUID();
        byte[] nonceBytes = new byte[32];
        random.nextBytes(nonceBytes);
        String nonce = Base64Url.encode(nonceBytes);
        OffsetDateTime expires = now().plusMinutes(5);
        jdbc.update(
                "insert into offline_activation_challenges(id,license_id,nonce,device_public_key,fingerprint_hash,fingerprint_version,expires_at) values(?,?,?,?,?,?,?)",
                id,
                license.getId(),
                nonce,
                request.devicePublicKey(),
                request.fingerprintHash(),
                request.fingerprintVersion(),
                expires);
        return new ChallengeResponse(
                id,
                nonce,
                Base64Url.encode(OfflineDeviceTokens.activationMessage(
                        id.toString(),
                        nonce,
                        request.productId().toString(),
                        request.licenseId().toString(),
                        request.devicePublicKey(),
                        request.fingerprintHash(),
                        request.fingerprintVersion())),
                expires);
    }

    @Transactional
    public Activated activate(ActivateRequest request) {
        if (request.challengeId() == null
                || request.idempotencyKey() == null
                || !request.idempotencyKey().matches("[A-Za-z0-9_-]{16,128}")) {
            throw new OfflineLicenseException(400, "invalid_activation_request");
        }
        byte[] signature = decoded(request.signature(), 64, false);
        License license = locked(request.licenseId(), request.productId());
        var rows = jdbc.query(
                "select * from offline_activation_challenges where id = ? and license_id = ? for update",
                (rs, row) -> new Challenge(
                        rs.getObject("id", UUID.class),
                        rs.getString("nonce"),
                        rs.getString("device_public_key"),
                        rs.getString("fingerprint_hash"),
                        rs.getInt("fingerprint_version"),
                        rs.getObject("expires_at", OffsetDateTime.class),
                        rs.getString("idempotency_key"),
                        rs.getString("request_signature"),
                        rs.getString("response_json")),
                request.challengeId(),
                license.getId());
        if (rows.isEmpty()) throw new OfflineLicenseException(404, "challenge_not_found");
        Challenge challenge = rows.getFirst();
        byte[] message = OfflineDeviceTokens.activationMessage(
                challenge.id().toString(),
                challenge.nonce(),
                request.productId().toString(),
                request.licenseId().toString(),
                challenge.devicePublicKey(),
                challenge.fingerprintHash(),
                challenge.fingerprintVersion());
        try {
            if (!Ed25519Verifier.fromBase64(challenge.devicePublicKey()).verify(message, signature)) {
                throw new OfflineLicenseException(401, "invalid_device_proof");
            }
        } catch (CryptoException e) {
            throw new OfflineLicenseException(401, "invalid_device_proof");
        }
        validContract(license);
        checkBinding(license, challenge.devicePublicKey(), challenge.fingerprintHash(), challenge.fingerprintVersion());
        if (challenge.response() != null) {
            if (!request.idempotencyKey().equals(challenge.idempotencyKey())
                    || !request.signature().equals(challenge.signature())) {
                throw new OfflineLicenseException(409, "idempotency_conflict");
            }
            try {
                return json.readValue(challenge.response(), Activated.class);
            } catch (JsonProcessingException e) {
                throw new IllegalStateException(e);
            }
        }
        if (!now().isBefore(challenge.expiresAt())) throw new OfflineLicenseException(422, "challenge_expired");
        Integer used = jdbc.queryForObject(
                "select count(*) from offline_activation_challenges where license_id = ? and idempotency_key = ?",
                Integer.class,
                license.getId(),
                request.idempotencyKey());
        if (used != null && used > 0) throw new OfflineLicenseException(409, "idempotency_conflict");
        Ed25519Signer signer = keys.signerForProduct(request.productId());
        long serverTime = clock.instant().getEpochSecond();
        if (serverTime >= license.getExpiresAt().toEpochSecond()) {
            throw new OfflineLicenseException(422, "license_expired");
        }
        String keyHash = OfflineDeviceTokens.keyHash(Base64.getDecoder().decode(challenge.devicePublicKey()));
        if (license.getBindingVersion() == 0) {
            license.setDevicePublicKey(challenge.devicePublicKey());
            license.setFingerprintHash(challenge.fingerprintHash());
            license.setFingerprintVersion(challenge.fingerprintVersion());
            license.setBindingVersion(1);
            license.setCertificateSerial(UUID.randomUUID());
            license.setStatus(LicenseStatus.ACTIVE);
            license.setActivatedAt(now());
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("ver", 2);
            claims.put("mode", "offline_device");
            claims.put("lid", license.getId().toString());
            claims.put("kid", license.getKeyId());
            claims.put("product_id", request.productId().toString());
            claims.put("prd", license.getProduct().getSlug());
            claims.put("serial", license.getCertificateSerial().toString());
            claims.put("revision", license.getRevision());
            claims.put("binding_version", 1);
            claims.put("device_key_hash", keyHash);
            claims.put("fingerprint_hash", challenge.fingerprintHash());
            claims.put("fingerprint_version", challenge.fingerprintVersion());
            claims.put("iat", serverTime);
            claims.put("nbf", serverTime);
            claims.put("exp", license.getExpiresAt().toEpochSecond());
            claims.put("ent", license.getEntitlements());
            claims.put("seat", 1);
            license.setSignedToken(OfflineDeviceTokens.sign(signer, "GMT", claims));
            license.setSigningKeyId(signer.signingKeyId());
            MachineActivation binding = new MachineActivation();
            binding.setLicense(license);
            binding.setFingerprint(challenge.fingerprintHash());
            activations.save(binding);
            audit.record(
                    "device:" + keyHash,
                    AuditActorType.SYSTEM,
                    "offline_license.activated",
                    "license",
                    license.getId().toString(),
                    Map.of("product_id", request.productId().toString(), "revision", license.getRevision()));
        }
        Map<String, Object> receipt = new LinkedHashMap<>();
        receipt.put("ver", 2);
        receipt.put("operation", "activate");
        receipt.put("challenge_id", challenge.id().toString());
        receipt.put("nonce", challenge.nonce());
        receipt.put("product_id", request.productId().toString());
        receipt.put("lid", license.getId().toString());
        receipt.put("device_key_hash", keyHash);
        receipt.put("serial", license.getCertificateSerial().toString());
        receipt.put("server_time", serverTime);
        Activated result = new Activated(
                license.getId(),
                license.getKeyId(),
                license.getSignedToken(),
                license.getRevision(),
                license.getBindingVersion(),
                serverTime,
                OfflineDeviceTokens.sign(signer, "GMT-TIME", receipt));
        try {
            jdbc.update(
                    "update offline_activation_challenges set consumed_at=?,idempotency_key=?,request_signature=?,response_json=? where id=?",
                    now(),
                    request.idempotencyKey(),
                    request.signature(),
                    json.writeValueAsString(result),
                    challenge.id());
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
        licenses.flush();
        return result;
    }

    private License locked(UUID id, UUID productId) {
        if (id == null || productId == null) throw new OfflineLicenseException(400, "invalid_activation_request");
        return licenses.findByIdForUpdate(id)
                .filter(l -> l.isOfflineDevice() && l.getProduct().getId().equals(productId))
                .orElseThrow(() -> new OfflineLicenseException(401, "invalid_activation_credentials"));
    }

    private void validContract(License license) {
        if (license.getStatus() != LicenseStatus.CREATED && license.getStatus() != LicenseStatus.ACTIVE)
            throw new OfflineLicenseException(422, "license_unavailable");
        if (!now().isBefore(license.getExpiresAt())) throw new OfflineLicenseException(422, "license_expired");
    }

    private static void checkBinding(License license, String publicKey, String fingerprint, int version) {
        if (license.getBindingVersion() != 0
                && (!publicKey.equals(license.getDevicePublicKey())
                        || !fingerprint.equals(license.getFingerprintHash())
                        || !Integer.valueOf(version).equals(license.getFingerprintVersion())))
            throw new OfflineLicenseException(409, "device_already_bound");
    }

    private static void validateDevice(String publicKey, String fingerprint, int version) {
        decoded(publicKey, 32, true);
        decoded(fingerprint, 32, false);
        if (version != 1) throw new OfflineLicenseException(400, "unsupported_fingerprint_version");
        try {
            Ed25519Verifier.fromBase64(publicKey);
        } catch (IllegalArgumentException | CryptoException e) {
            throw new OfflineLicenseException(400, "invalid_device_key");
        }
    }

    private static byte[] decoded(String value, int length, boolean standard) {
        try {
            if (value == null || value.length() > 128) throw new IllegalArgumentException();
            byte[] bytes = (standard ? Base64.getDecoder() : Base64.getUrlDecoder()).decode(value);
            String encoded =
                    (standard ? Base64.getEncoder() : Base64.getUrlEncoder().withoutPadding()).encodeToString(bytes);
            if (bytes.length != length || !value.equals(encoded)) throw new IllegalArgumentException();
            return bytes;
        } catch (IllegalArgumentException e) {
            throw new OfflineLicenseException(400, "invalid_device_encoding");
        }
    }

    @Scheduled(fixedDelayString = "PT1H")
    public void purgeChallenges() {
        jdbc.update(
                "delete from offline_activation_challenges where expires_at < ? and (response_json is null or consumed_at < ?)",
                now(),
                now().minusDays(1));
    }

    private OffsetDateTime now() {
        return OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
    }
}
