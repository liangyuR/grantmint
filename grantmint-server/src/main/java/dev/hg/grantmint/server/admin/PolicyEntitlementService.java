package dev.hg.grantmint.server.admin;

import dev.hg.grantmint.core.entitlement.EntitlementKey;
import dev.hg.grantmint.core.entitlement.EntitlementSet;
import dev.hg.grantmint.server.domain.Entitlement;
import dev.hg.grantmint.server.domain.Policy;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.repo.EntitlementRepository;
import dev.hg.grantmint.server.repo.PolicyRepository;
import dev.hg.grantmint.server.repo.ProductRepository;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Admin CRUD for {@link Policy} and its child {@link Entitlement} rows. After every entitlement
 * mutation (create/update/delete) and after every policy save, the policy's denormalized
 * {@code entitlements} jsonb snapshot is rebuilt via {@link EntitlementSet} so it stays byte-
 * identical to what is embedded in signed tokens.
 */
@Service
public class PolicyEntitlementService {

    private final PolicyRepository policyRepo;
    private final EntitlementRepository entitlementRepo;
    private final ProductRepository productRepo;

    public PolicyEntitlementService(
            PolicyRepository policyRepo, EntitlementRepository entitlementRepo, ProductRepository productRepo) {
        this.policyRepo = policyRepo;
        this.entitlementRepo = entitlementRepo;
        this.productRepo = productRepo;
    }

    // ─── Policy CRUD ─────────────────────────────────────────────────────────────

    @Transactional
    public Policy createPolicy(UUID productId, CreatePolicyCommand cmd) {
        Product product = productRepo
                .findById(productId)
                .orElseThrow(() -> new NoSuchElementException("Product not found: " + productId));
        if (policyRepo.findByProduct_IdAndCode(productId, cmd.code()).isPresent()) {
            throw new IllegalArgumentException("Policy code already exists for this product: " + cmd.code());
        }
        Policy policy = new Policy();
        policy.setProduct(product);
        policy.setCode(cmd.code());
        policy.setName(cmd.name());
        applyUpdatableFields(
                policy,
                cmd.activationType(),
                cmd.maxSeats(),
                cmd.durationDays(),
                cmd.gracePeriodDays(),
                cmd.trial(),
                cmd.heartbeatIntervalSeconds(),
                cmd.constraints());
        Policy saved = policyRepo.save(policy);
        rebuildSnapshot(saved);
        return saved;
    }

    @Transactional(readOnly = true)
    public List<Policy> listPolicies(UUID productId) {
        if (!productRepo.existsById(productId)) {
            throw new NoSuchElementException("Product not found: " + productId);
        }
        return policyRepo.findByProduct_Id(productId);
    }

    @Transactional(readOnly = true)
    public Policy getPolicy(UUID policyId) {
        return policyRepo
                .findById(policyId)
                .orElseThrow(() -> new NoSuchElementException("Policy not found: " + policyId));
    }

    @Transactional
    public Policy updatePolicy(UUID policyId, UpdatePolicyCommand cmd) {
        Policy policy = getPolicy(policyId);
        policy.setName(cmd.name());
        applyUpdatableFields(
                policy,
                cmd.activationType(),
                cmd.maxSeats(),
                cmd.durationDays(),
                cmd.gracePeriodDays(),
                cmd.trial(),
                cmd.heartbeatIntervalSeconds(),
                cmd.constraints());
        Policy saved = policyRepo.save(policy);
        rebuildSnapshot(saved);
        return saved;
    }

    @Transactional
    public void deletePolicy(UUID policyId) {
        Policy policy = getPolicy(policyId);
        entitlementRepo.deleteByPolicy_Id(policyId);
        policyRepo.delete(policy);
    }

    // ─── Entitlement CRUD ────────────────────────────────────────────────────────

    @Transactional
    public Entitlement createEntitlement(UUID policyId, String code, String valueType, Object rawValue) {
        // Same canonical grammar the token codec, all four SDK verifiers, and the DB CHECK
        // (ck_entitlements_code_fmt) enforce — validated here so a bad code is a clean 400
        // bad_request, not a raw constraint-violation surprise (GRANTMINT-170).
        if (code == null || !EntitlementKey.isCanonical(code)) {
            throw new IllegalArgumentException(
                    "entitlement code must be canonical snake_case matching ^[a-z][a-z0-9_]{0,62}$, got: " + code);
        }
        Policy policy = getPolicy(policyId);
        Map<String, Object> valueMap = buildValueMap(valueType, rawValue);
        Entitlement entitlement = new Entitlement();
        entitlement.setPolicy(policy);
        entitlement.setCode(code);
        entitlement.setValueType(valueType);
        entitlement.setValue(valueMap);
        Entitlement saved = entitlementRepo.save(entitlement);
        rebuildSnapshot(policy);
        return saved;
    }

    @Transactional(readOnly = true)
    public List<Entitlement> listEntitlements(UUID policyId) {
        if (!policyRepo.existsById(policyId)) {
            throw new NoSuchElementException("Policy not found: " + policyId);
        }
        return entitlementRepo.findByPolicy_Id(policyId);
    }

    @Transactional
    public Entitlement updateEntitlement(UUID policyId, UUID entitlementId, String valueType, Object rawValue) {
        Policy policy = getPolicy(policyId);
        Entitlement entitlement = entitlementRepo
                .findById(entitlementId)
                .orElseThrow(() -> new NoSuchElementException("Entitlement not found: " + entitlementId));
        if (!entitlement.getPolicy().getId().equals(policyId)) {
            throw new NoSuchElementException("Entitlement not found: " + entitlementId);
        }
        Map<String, Object> valueMap = buildValueMap(valueType, rawValue);
        entitlement.setValueType(valueType);
        entitlement.setValue(valueMap);
        Entitlement saved = entitlementRepo.save(entitlement);
        rebuildSnapshot(policy);
        return saved;
    }

    @Transactional
    public void deleteEntitlement(UUID policyId, UUID entitlementId) {
        Policy policy = getPolicy(policyId);
        Entitlement entitlement = entitlementRepo
                .findById(entitlementId)
                .orElseThrow(() -> new NoSuchElementException("Entitlement not found: " + entitlementId));
        if (!entitlement.getPolicy().getId().equals(policyId)) {
            throw new NoSuchElementException("Entitlement not found: " + entitlementId);
        }
        entitlementRepo.delete(entitlement);
        rebuildSnapshot(policy);
    }

    // ─── Snapshot rebuild ────────────────────────────────────────────────────────

    /**
     * Rebuild the policy's denormalized entitlements snapshot from the normalized {@code entitlements}
     * table rows. Uses {@link EntitlementSet} to ensure the encoding is byte-identical to what the
     * signed token embeds.
     *
     * <p>Called after every entitlement create/update/delete and after every policy create/update.
     */
    void rebuildSnapshot(Policy policy) {
        List<dev.hg.grantmint.core.entitlement.Entitlement> coreEntitlements =
                entitlementRepo.findByPolicy_Id(policy.getId()).stream()
                        .map(this::toCore)
                        .toList();
        EntitlementSet set = EntitlementSet.of(coreEntitlements);
        policy.setEntitlements(new LinkedHashMap<>(set.encode()));
        policyRepo.save(policy);
    }

    private dev.hg.grantmint.core.entitlement.Entitlement toCore(Entitlement e) {
        return switch (e.getValueType()) {
            case "flag" -> dev.hg.grantmint.core.entitlement.Entitlement.flag(
                    e.getCode(), (Boolean) e.getValue().get("bool"));
            case "limit" -> dev.hg.grantmint.core.entitlement.Entitlement.limit(
                    e.getCode(), ((Number) e.getValue().get("int")).longValue());
            case "string" -> dev.hg.grantmint.core.entitlement.Entitlement.string(
                    e.getCode(), (String) e.getValue().get("string"));
            default -> throw new IllegalArgumentException("Unknown value_type: " + e.getValueType());
        };
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────────

    /**
     * Build the DB-wire value map ({@code {"bool":..}} / {@code {"int":..}} / {@code {"string":..}})
     * from the request's typed raw value.
     */
    private Map<String, Object> buildValueMap(String valueType, Object rawValue) {
        return switch (valueType) {
            case "flag" -> {
                if (!(rawValue instanceof Boolean)) {
                    throw new IllegalArgumentException("value must be a boolean for valueType 'flag'");
                }
                yield Map.of("bool", rawValue);
            }
            case "limit" -> {
                if (!(rawValue instanceof Number)) {
                    throw new IllegalArgumentException("value must be a number for valueType 'limit'");
                }
                yield Map.of("int", ((Number) rawValue).longValue());
            }
            case "string" -> {
                if (!(rawValue instanceof String)) {
                    throw new IllegalArgumentException("value must be a string for valueType 'string'");
                }
                yield Map.of("string", rawValue);
            }
            default -> throw new IllegalArgumentException(
                    "Unknown valueType: " + valueType + ". Must be flag, limit, or string");
        };
    }

    private void applyUpdatableFields(
            Policy policy,
            String activationType,
            Integer maxSeats,
            Integer durationDays,
            Integer gracePeriodDays,
            Boolean trial,
            Integer heartbeatIntervalSeconds,
            Map<String, Object> constraints) {
        if (activationType != null) {
            policy.setActivationType(activationType);
        }
        if (maxSeats != null) {
            policy.setMaxSeats(maxSeats);
        }
        policy.setDurationDays(durationDays);
        if (gracePeriodDays != null) {
            policy.setGracePeriodDays(gracePeriodDays);
        }
        if (trial != null) {
            policy.setTrial(trial);
        }
        if (heartbeatIntervalSeconds != null) {
            policy.setHeartbeatIntervalSeconds(heartbeatIntervalSeconds);
        }
        if (constraints != null) {
            policy.setConstraints(constraints);
        }
    }

    // ─── Command records ──────────────────────────────────────────────────────────

    public record CreatePolicyCommand(
            String code,
            String name,
            String activationType,
            Integer maxSeats,
            Integer durationDays,
            Integer gracePeriodDays,
            Boolean trial,
            Integer heartbeatIntervalSeconds,
            Map<String, Object> constraints) {}

    public record UpdatePolicyCommand(
            String name,
            String activationType,
            Integer maxSeats,
            Integer durationDays,
            Integer gracePeriodDays,
            Boolean trial,
            Integer heartbeatIntervalSeconds,
            Map<String, Object> constraints) {}
}
