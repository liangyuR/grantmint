-- V7: index gaps found by the M13 phase audit (Category 3). Three read paths ran as
-- sequential scans, and one partial index could not serve its admin query shape.
--
-- Like V5, the one index this migration drops is replaced in the same migration — later
-- migrations never edit earlier ones (Flyway checksums stay intact).

-- ── signing_keys.product_id ──────────────────────────────────────────────────
-- Postgres does not auto-index FK columns. SigningKeyService resolves a product's keys on
-- every issuance signer build and on the admin list — both filtered by product_id.
CREATE INDEX ix_signing_keys_product ON signing_keys (product_id);

-- ── api_keys by product: partial → full ─────────────────────────────────────
-- V2's ix_api_keys_product carried WHERE revoked_at IS NULL, but the admin key list
-- (ApiKeyRepository.findByProduct_IdOrderByCreatedAtDesc) must show revoked keys too, so
-- once any key was revoked the partial index could no longer cover the query. A full
-- (product_id) index serves both the admin list and any live-keys-only filter; the table
-- is small, so the wider index costs little.
DROP INDEX ix_api_keys_product;
CREATE INDEX ix_api_keys_product ON api_keys (product_id);

-- ── licenses.status ──────────────────────────────────────────────────────────
-- Backs the grantmint.licenses.active Prometheus gauge (LicenseRepository.countByStatus),
-- sampled on every scrape — a low-cardinality B-tree that turns a per-scrape full-table
-- aggregate into an index-only scan.
CREATE INDEX ix_licenses_status ON licenses (status);
