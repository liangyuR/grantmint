package dev.hg.grantmint.server.webhook;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A provider-neutral view of a verified, parsed webhook event: the provider's stable event id
 * (idempotency key), its event type string, and the event's data object. Distinct from the
 * {@code server.domain.WebhookEvent} JPA entity, which is the persisted idempotency ledger row this
 * record gets written into.
 */
public record WebhookEvent(String id, String type, JsonNode data) {}
