CREATE TABLE applications (
 id uuid PRIMARY KEY, slug text UNIQUE NOT NULL, name text NOT NULL, description text NOT NULL DEFAULT '',
 signing_key_id text NOT NULL, archived_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE signing_keys (
 key_id text PRIMARY KEY, application_id uuid NOT NULL REFERENCES applications(id), public_key text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE licenses (
 id uuid PRIMARY KEY, application_id uuid NOT NULL REFERENCES applications(id), key_id text UNIQUE NOT NULL,
 customer jsonb NOT NULL, expires_at timestamptz NOT NULL, entitlements jsonb NOT NULL DEFAULT '{}',
 activation_secret_hash bytea NOT NULL CHECK(octet_length(activation_secret_hash)=32),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision BETWEEN 1 AND 9007199254740991),
 revoked_at timestamptz, revoke_reason text, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE device_bindings (
 license_id uuid PRIMARY KEY REFERENCES licenses(id), device_public_key text NOT NULL,
 fingerprint_hash text NOT NULL, fingerprint_version integer NOT NULL CHECK(fingerprint_version=1),
 binding_version bigint NOT NULL DEFAULT 1 CHECK(binding_version=1), bound_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE certificates (
 license_id uuid NOT NULL REFERENCES licenses(id), revision bigint NOT NULL, binding_version bigint NOT NULL,
 serial uuid UNIQUE NOT NULL, key_id text NOT NULL REFERENCES signing_keys(key_id), token text NOT NULL,
 confirmed_at timestamptz, reason text NOT NULL, issued_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(license_id,revision,binding_version)
);
CREATE TABLE challenges (
 id uuid PRIMARY KEY, license_id uuid NOT NULL REFERENCES licenses(id), operation text NOT NULL CHECK(operation IN('activate','sync','ack')),
 nonce text NOT NULL, device_public_key text NOT NULL, fingerprint_hash text NOT NULL, fingerprint_version integer NOT NULL CHECK(fingerprint_version=1),
 serial uuid, expires_at timestamptz NOT NULL, consumed_at timestamptz,
 idempotency_key text, request_hash bytea, response jsonb
);
CREATE UNIQUE INDEX challenge_idempotency ON challenges(license_id,operation,idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX challenge_expiry ON challenges(expires_at);
CREATE TABLE renewals (
 id uuid PRIMARY KEY, license_id uuid NOT NULL REFERENCES licenses(id), idempotency_key text NOT NULL,
 request_hash bytea NOT NULL, old_expires_at timestamptz NOT NULL, new_expires_at timestamptz NOT NULL,
 revision bigint NOT NULL, serial uuid, actor text NOT NULL, reason text NOT NULL,
 confirmed_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), response jsonb NOT NULL,
 UNIQUE(license_id,idempotency_key)
);
CREATE TABLE admin_users (
 id uuid PRIMARY KEY, username text UNIQUE NOT NULL, password_hash text NOT NULL, disabled boolean NOT NULL DEFAULT false
);
CREATE TABLE admin_sessions (
 token_hash bytea PRIMARY KEY, admin_id uuid NOT NULL REFERENCES admin_users(id), csrf_token text NOT NULL,
 expires_at timestamptz NOT NULL
);
CREATE TABLE audit_events (
 id bigserial PRIMARY KEY, actor text NOT NULL, application_id uuid, license_id uuid,
 action text NOT NULL, detail jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_application_time ON audit_events(application_id,created_at DESC);
CREATE INDEX license_application_created ON licenses(application_id,created_at DESC);
