ALTER TABLE licenses ALTER COLUMN signed_token DROP NOT NULL;
ALTER TABLE licenses ALTER COLUMN signing_key_id DROP NOT NULL;
ALTER TABLE licenses ADD COLUMN mode text NOT NULL DEFAULT 'legacy_v1';
ALTER TABLE licenses ADD COLUMN revision integer NOT NULL DEFAULT 1;
ALTER TABLE licenses ADD COLUMN binding_version integer NOT NULL DEFAULT 0;
ALTER TABLE licenses ADD COLUMN activation_secret_hash text;
ALTER TABLE licenses ADD COLUMN device_public_key text;
ALTER TABLE licenses ADD COLUMN fingerprint_hash text;
ALTER TABLE licenses ADD COLUMN fingerprint_version integer;
ALTER TABLE licenses ADD COLUMN certificate_serial uuid;
ALTER TABLE licenses ADD CONSTRAINT ck_offline_versions CHECK (revision >= 1 AND binding_version >= 0);
ALTER TABLE licenses ADD CONSTRAINT ck_license_mode CHECK (mode IN ('legacy_v1', 'offline_device_v2'));
ALTER TABLE licenses ADD CONSTRAINT ck_legacy_certificate CHECK (mode <> 'legacy_v1' OR (signed_token IS NOT NULL AND signing_key_id IS NOT NULL));
ALTER TABLE licenses ADD CONSTRAINT ck_offline_contract CHECK (mode <> 'offline_device_v2' OR (max_seats = 1 AND expires_at IS NOT NULL AND activation_secret_hash IS NOT NULL));
ALTER TABLE licenses ADD CONSTRAINT ck_offline_binding CHECK (mode <> 'offline_device_v2' OR
  (binding_version = 0 AND device_public_key IS NULL AND fingerprint_hash IS NULL AND fingerprint_version IS NULL AND signed_token IS NULL AND signing_key_id IS NULL AND certificate_serial IS NULL) OR
  (binding_version = 1 AND device_public_key IS NOT NULL AND fingerprint_hash IS NOT NULL AND fingerprint_version IS NOT NULL AND fingerprint_version = 1 AND signed_token IS NOT NULL AND signing_key_id IS NOT NULL AND certificate_serial IS NOT NULL));
CREATE TABLE offline_activation_challenges (
  id uuid PRIMARY KEY,
  license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  nonce text NOT NULL,
  device_public_key text NOT NULL,
  fingerprint_hash text NOT NULL,
  fingerprint_version integer NOT NULL CHECK (fingerprint_version = 1),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  idempotency_key text,
  request_signature text,
  response_json text
);
CREATE UNIQUE INDEX uq_offline_activation_request ON offline_activation_challenges(license_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX ix_offline_challenge_expiry ON offline_activation_challenges(expires_at);
