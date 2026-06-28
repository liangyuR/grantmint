-- V2__validation_indexes.sql — hot-path and background-sweep indexes.
--
-- Tuned for the read-heavy validation hot path (lookup by key ID, count seats) and the
-- background sweeps (expiry, heartbeat timeout). See docs/architecture/DATABASE_SCHEMA.md
-- (Indexing Strategy) and docs/reference/PERFORMANCE_OPTIMIZATION.md.
--
-- Note: uq_licenses_key_id, uq_api_keys_hash and uq_webhook_provider_event already provide
-- B-tree indexes on their columns; only the supplementary indexes are created here.

-- ── Validation hot path ──────────────────────────────────────────────────────
-- Only ACTIVE licenses matter on the hot path; a partial index keeps it tiny & cache-hot.
CREATE INDEX ix_licenses_key_id_active
    ON licenses (key_id)
    WHERE status = 'active';

-- ── Seat counting ────────────────────────────────────────────────────────────
-- Count active seats for a license quickly during activation.
CREATE INDEX ix_activations_license_active
    ON machine_activations (license_id)
    WHERE status = 'active';

-- General lookups of all activations for a license (dashboard).
CREATE INDEX ix_activations_license
    ON machine_activations (license_id);

-- ── Customer / admin lookups ─────────────────────────────────────────────────
CREATE INDEX ix_licenses_holder_email ON licenses (lower(holder_email));
CREATE INDEX ix_licenses_product      ON licenses (product_id);
CREATE INDEX ix_licenses_policy       ON licenses (policy_id);
CREATE INDEX ix_licenses_external_ref ON licenses (external_ref);

-- ── Background jobs ──────────────────────────────────────────────────────────
-- Expiry sweep: find non-terminal licenses whose expiry has passed.
CREATE INDEX ix_licenses_expiry_sweep
    ON licenses (expires_at)
    WHERE status IN ('active', 'suspended') AND expires_at IS NOT NULL;

-- Heartbeat-timeout sweep: find active activations that went quiet.
CREATE INDEX ix_activations_heartbeat
    ON machine_activations (last_heartbeat_at)
    WHERE status = 'active';

-- ── Entitlement / policy joins ───────────────────────────────────────────────
CREATE INDEX ix_entitlements_policy ON entitlements (policy_id);
CREATE INDEX ix_policies_product    ON policies (product_id);

-- GIN index for querying inside the entitlement payload (e.g. "licenses with team_sync").
CREATE INDEX ix_licenses_entitlements_gin
    ON licenses USING gin (entitlements jsonb_path_ops);

-- ── API keys ─────────────────────────────────────────────────────────────────
CREATE INDEX ix_api_keys_product
    ON api_keys (product_id)
    WHERE revoked_at IS NULL;

-- ── Webhooks ─────────────────────────────────────────────────────────────────
CREATE INDEX ix_webhook_events_unprocessed
    ON webhook_events (received_at)
    WHERE status = 'received';

-- ── Audit ────────────────────────────────────────────────────────────────────
CREATE INDEX ix_audit_target   ON audit_log (target_type, target_id);
CREATE INDEX ix_audit_occurred ON audit_log (occurred_at DESC);
