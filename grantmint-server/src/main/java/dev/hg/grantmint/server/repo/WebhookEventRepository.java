package dev.hg.grantmint.server.repo;

import dev.hg.grantmint.server.domain.WebhookEvent;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Ingested billing webhook events. Idempotency is enforced by the unique (provider,
 * provider_event_id) pair so that redelivered events are no-ops.
 */
public interface WebhookEventRepository extends JpaRepository<WebhookEvent, UUID> {

    boolean existsByProviderAndProviderEventId(String provider, String providerEventId);

    Optional<WebhookEvent> findByProviderAndProviderEventId(String provider, String providerEventId);
}
