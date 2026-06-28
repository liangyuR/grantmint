package dev.hg.grantmint.server.repo;

import dev.hg.grantmint.server.domain.Entitlement;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Normalized per-policy entitlement rows; the editable source for the policy snapshot. */
public interface EntitlementRepository extends JpaRepository<Entitlement, UUID> {

    List<Entitlement> findByPolicy_Id(UUID policyId);

    void deleteByPolicy_Id(UUID policyId);
}
