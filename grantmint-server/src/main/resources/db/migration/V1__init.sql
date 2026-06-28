-- V1__init.sql — Grantmint base schema.
--
-- Authoritative reference: docs/architecture/DATABASE_SCHEMA.md.
-- Targets PostgreSQL 15+. A fresh deploy is a single ordered Flyway run from an empty
-- database to the current schema. Never edit this migration once released; add a new
-- V<n+1> instead.
--
-- 🔒 Security invariants enforced structurally here:
--   * The Ed25519 PRIVATE signing key never lives in this database. signing_keys stores the
--     public key plus a private_key_ref POINTER, guarded by ck_signing_keys_ref_is_pointer.
--   * Migrations and seeds never insert private key material.

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()

-- ─────────────────────────────────────────────────────────────────────────────
-- products
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE products (
    id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    slug                  TEXT         NOT NULL,
    name                  TEXT         NOT NULL,
    description           TEXT,
    -- Short key ID (kid) of the active signing key. Private key lives outside the DB.
    -- FK wired after signing_keys exists (see below).
    active_signing_key_id TEXT,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT uq_products_slug     UNIQUE (slug),
    CONSTRAINT ck_products_slug_fmt CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$')
);

COMMENT ON COLUMN products.active_signing_key_id IS
    'Short key ID (kid) of the active signing key. Private key lives outside the DB.';

-- ─────────────────────────────────────────────────────────────────────────────
-- signing_keys — Ed25519 key metadata + PUBLIC key only. No private bytes. 🔒
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE signing_keys (
    key_id          TEXT         PRIMARY KEY,            -- short kid, e.g. 'ed25519-2026-01'
    product_id      UUID         NOT NULL,
    algorithm       TEXT         NOT NULL DEFAULT 'Ed25519',
    public_key      BYTEA        NOT NULL,               -- 32-byte raw Ed25519 public key
    -- Pointer ONLY. Never the private bytes. e.g. 'vault:secret/grantmint/sign#2026'.
    private_key_ref TEXT         NOT NULL,
    status          TEXT         NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ,                         -- set when superseded
    retired_at      TIMESTAMPTZ,                         -- set when no longer trusted

    CONSTRAINT fk_signing_keys_product
        FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE,
    CONSTRAINT ck_signing_keys_algo
        CHECK (algorithm = 'Ed25519'),
    CONSTRAINT ck_signing_keys_status
        CHECK (status IN ('active', 'rotating', 'retired')),
    CONSTRAINT ck_signing_keys_pubkey_len
        CHECK (octet_length(public_key) = 32),
    -- Guard rail: refuse anything that does not look like a reference scheme, making it
    -- structurally hard to paste raw private key bytes into the database. 🔒
    CONSTRAINT ck_signing_keys_ref_is_pointer
        CHECK (private_key_ref ~ '^(file:|vault:|env:|awssm:|gcpsm:|sops:)')
);

COMMENT ON COLUMN signing_keys.public_key IS '32-byte raw Ed25519 public key; also embedded in clients.';
COMMENT ON COLUMN signing_keys.private_key_ref IS 'Pointer to private key (file:/vault:/env:/...); never the bytes.';

-- Now wire the deferred product FK back to the signing key.
ALTER TABLE products
    ADD CONSTRAINT fk_products_active_signing_key
        FOREIGN KEY (active_signing_key_id) REFERENCES signing_keys (key_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- api_keys — per-product issuance/validation/admin keys. Hash only. 🔒
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE api_keys (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id   UUID,                                   -- NULL for global admin keys
    name         TEXT         NOT NULL,
    -- Argon2id/SHA-256 hash of the secret. The plaintext key is shown ONCE at creation.
    key_hash     TEXT         NOT NULL,
    key_prefix   TEXT         NOT NULL,                  -- first 8 chars, for display/lookup
    scope        TEXT         NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,

    CONSTRAINT fk_api_keys_product
        FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE,
    CONSTRAINT uq_api_keys_hash UNIQUE (key_hash),
    CONSTRAINT ck_api_keys_scope
        CHECK (scope IN ('issuance', 'validation', 'admin')),
    -- Issuance and validation keys MUST be scoped to a product; admin keys may be global.
    CONSTRAINT ck_api_keys_product_scope
        CHECK (scope = 'admin' OR product_id IS NOT NULL)
);

COMMENT ON COLUMN api_keys.key_hash IS 'Hash only. Plaintext is never stored.';

-- ─────────────────────────────────────────────────────────────────────────────
-- policies — license template/tier for a product.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE policies (
    id                         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id                 UUID         NOT NULL,
    code                       TEXT         NOT NULL,    -- e.g. 'pro-annual'
    name                       TEXT         NOT NULL,    -- e.g. 'Pro Annual'
    activation_type            TEXT         NOT NULL DEFAULT 'node_locked',
    max_seats                  INTEGER      NOT NULL DEFAULT 1,
    duration_days              INTEGER,                  -- NULL = perpetual
    grace_period_days          INTEGER      NOT NULL DEFAULT 0,
    is_trial                   BOOLEAN      NOT NULL DEFAULT false,
    -- Denormalized snapshot of this policy's entitlements, exactly as serialized into the
    -- signed token. The normalized source of truth is the entitlements table.
    entitlements               JSONB        NOT NULL DEFAULT '{}'::jsonb,
    -- Optional issuance-time constraints embedded into every token.
    constraints                JSONB        NOT NULL DEFAULT '{}'::jsonb,
    heartbeat_interval_seconds INTEGER      NOT NULL DEFAULT 86400,
    created_at                 TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT fk_policies_product
        FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE,
    CONSTRAINT uq_policies_product_code UNIQUE (product_id, code),
    CONSTRAINT ck_policies_activation
        CHECK (activation_type IN ('node_locked', 'floating')),
    CONSTRAINT ck_policies_max_seats CHECK (max_seats >= 1),
    CONSTRAINT ck_policies_duration  CHECK (duration_days IS NULL OR duration_days > 0),
    CONSTRAINT ck_policies_grace     CHECK (grace_period_days >= 0),
    CONSTRAINT ck_policies_heartbeat CHECK (heartbeat_interval_seconds >= 60)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- entitlements — normalized, per-policy named capabilities and limits.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE entitlements (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id  UUID         NOT NULL,
    code       TEXT         NOT NULL,                    -- e.g. 'team_sync', 'max_devices'
    value_type TEXT         NOT NULL,                    -- flag | limit | string
    value      JSONB        NOT NULL,                    -- e.g. {"bool":true} / {"int":5}
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT fk_entitlements_policy
        FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE,
    CONSTRAINT uq_entitlements_policy_code UNIQUE (policy_id, code),
    CONSTRAINT ck_entitlements_value_type
        CHECK (value_type IN ('flag', 'limit', 'string')),
    CONSTRAINT ck_entitlements_code_fmt
        CHECK (code ~ '^[a-z][a-z0-9_]{0,62}$')
);

-- ─────────────────────────────────────────────────────────────────────────────
-- licenses — an issued instance of a policy for a customer. PII-bearing. 🔒
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE licenses (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id        UUID         NOT NULL,
    policy_id         UUID         NOT NULL,
    -- Short, human-readable ONLINE identifier. e.g. 'GMNT-7F3A-9K2D-XQ41'.
    key_id            TEXT         NOT NULL,
    -- Full Ed25519-signed OFFLINE artifact (base64url). Immutable once written.
    signed_token      TEXT         NOT NULL,
    -- Which signing key minted this token (supports rotation/audit).
    signing_key_id    TEXT         NOT NULL,
    status            TEXT         NOT NULL DEFAULT 'created',
    holder_name       TEXT,                              -- PII
    holder_email      TEXT,                              -- PII
    -- Effective entitlements snapshot at issuance (copied from policy, may be overridden).
    entitlements      JSONB        NOT NULL DEFAULT '{}'::jsonb,
    constraints       JSONB        NOT NULL DEFAULT '{}'::jsonb,
    max_seats         INTEGER      NOT NULL,             -- snapshot of policy at issuance
    issued_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    activated_at      TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ,                       -- NULL = perpetual
    suspended_at      TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ,
    revocation_reason TEXT,
    external_ref      TEXT,                              -- e.g. Stripe subscription id
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT fk_licenses_product
        FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE RESTRICT,
    CONSTRAINT fk_licenses_policy
        FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE RESTRICT,
    CONSTRAINT fk_licenses_signing_key
        FOREIGN KEY (signing_key_id) REFERENCES signing_keys (key_id),
    CONSTRAINT uq_licenses_key_id UNIQUE (key_id),
    CONSTRAINT ck_licenses_status
        CHECK (status IN ('created', 'active', 'suspended', 'expired', 'revoked')),
    CONSTRAINT ck_licenses_max_seats CHECK (max_seats >= 1),
    -- A revoked license must carry a revoked_at timestamp.
    CONSTRAINT ck_licenses_revoked_consistency
        CHECK (status <> 'revoked' OR revoked_at IS NOT NULL),
    CONSTRAINT ck_licenses_email_fmt
        CHECK (holder_email IS NULL OR holder_email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$')
);

COMMENT ON COLUMN licenses.key_id IS 'Online lookup handle (unique).';
COMMENT ON COLUMN licenses.signed_token IS 'Self-contained offline artifact; verifies via embedded public key.';

-- ─────────────────────────────────────────────────────────────────────────────
-- machine_activations — a device that activated a license. Counts against seats. 🔒
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE machine_activations (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    license_id        UUID         NOT NULL,
    -- Stable device fingerprint (hashed hardware/OS signal). Unique per license.
    fingerprint       TEXT         NOT NULL,
    machine_name      TEXT,                              -- human label, optional
    platform          TEXT,                              -- 'macos' | 'windows' | 'linux' | ...
    status            TEXT         NOT NULL DEFAULT 'active',
    activated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_heartbeat_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deactivated_at    TIMESTAMPTZ,
    ip_address        INET,                              -- last seen; PII-adjacent
    metadata          JSONB        NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT fk_activations_license
        FOREIGN KEY (license_id) REFERENCES licenses (id) ON DELETE CASCADE,
    -- A given device may hold at most one activation row per license (idempotent re-activate).
    CONSTRAINT uq_activations_license_fingerprint UNIQUE (license_id, fingerprint),
    CONSTRAINT ck_activations_status
        CHECK (status IN ('active', 'deactivated', 'expired'))
);

-- NOTE: seat limits are enforced in application logic inside a transaction
-- (SELECT ... FOR UPDATE the license, count active seats) — there is no declarative DB
-- constraint for it. See docs/features/ACTIVATION_AND_SEATS.md.

-- ─────────────────────────────────────────────────────────────────────────────
-- webhook_events — ingested billing webhook events. Idempotent via provider event ID.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE webhook_events (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id           UUID,
    provider             TEXT         NOT NULL,          -- 'stripe' | 'polar' | ...
    provider_event_id    TEXT         NOT NULL,          -- e.g. Stripe 'evt_...'
    event_type           TEXT         NOT NULL,          -- e.g. 'customer.subscription.deleted'
    status               TEXT         NOT NULL DEFAULT 'received',
    payload              JSONB        NOT NULL,          -- raw verified event body
    signature_valid      BOOLEAN      NOT NULL,
    received_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    processed_at         TIMESTAMPTZ,
    error_detail         TEXT,
    resulting_license_id UUID,                           -- license created/changed, if any

    CONSTRAINT fk_webhook_events_product
        FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE SET NULL,
    CONSTRAINT fk_webhook_events_license
        FOREIGN KEY (resulting_license_id) REFERENCES licenses (id) ON DELETE SET NULL,
    -- Idempotency: a provider event is processed at most once.
    CONSTRAINT uq_webhook_provider_event UNIQUE (provider, provider_event_id),
    CONSTRAINT ck_webhook_status
        CHECK (status IN ('received', 'processed', 'failed', 'ignored'))
);

-- ─────────────────────────────────────────────────────────────────────────────
-- audit_log — append-only record of who issued/revoked/changed what.
-- Loose (target_type, target_id) reference, deliberately NOT FK-constrained so audit
-- rows survive target deletion.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE audit_log (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    actor       TEXT         NOT NULL,                   -- admin username / api key id / 'webhook:stripe'
    actor_type  TEXT         NOT NULL,                   -- 'admin' | 'api_key' | 'webhook' | 'system'
    action      TEXT         NOT NULL,                   -- 'license.issued', 'license.revoked', ...
    target_type TEXT         NOT NULL,                   -- 'license' | 'policy' | 'product' | ...
    target_id   TEXT,
    detail      JSONB        NOT NULL DEFAULT '{}'::jsonb,
    ip_address  INET,
    occurred_at TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT ck_audit_actor_type
        CHECK (actor_type IN ('admin', 'api_key', 'webhook', 'system'))
);
