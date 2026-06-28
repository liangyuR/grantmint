-- V3__admin_auth.sql — Scheme 1 (admin / dashboard auth): password + server-side sessions.
--
-- Authoritative reference: docs/features/ADMIN_AND_API_AUTH.md (Scheme 1).
-- Never edit this migration once released; add a new V<n+1> instead.
--
-- 🔒 Security invariants enforced structurally here:
--   * Admin passwords are stored only as an Argon2id PHC hash — never plaintext.
--   * Session bearer tokens are stored only as a SHA-256 hash; the opaque token is shown once.
--     The operator can revoke any session instantly (delete the row), so the admin surface
--     favours revocability over statelessness.

-- ─────────────────────────────────────────────────────────────────────────────
-- admin_users — operators who manage products, policies, licenses, and API keys. 🔒
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE admin_users (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT         NOT NULL,
    -- Argon2id PHC string, e.g. '$argon2id$v=19$m=...$...'. Never plaintext.
    password_hash TEXT         NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    disabled_at   TIMESTAMPTZ,

    CONSTRAINT uq_admin_users_username UNIQUE (username),
    CONSTRAINT ck_admin_users_username_fmt
        CHECK (char_length(username) BETWEEN 1 AND 64)
);

COMMENT ON COLUMN admin_users.password_hash IS 'Argon2id PHC hash; never plaintext.';

-- ─────────────────────────────────────────────────────────────────────────────
-- admin_sessions — opaque server-side session tokens. Hash only. 🔒
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE admin_sessions (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_user_id UUID         NOT NULL,
    -- SHA-256 hex of the opaque 'gm_sess_…' bearer token. The token itself is shown once.
    token_hash    TEXT         NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ  NOT NULL,
    revoked_at    TIMESTAMPTZ,

    CONSTRAINT fk_admin_sessions_user
        FOREIGN KEY (admin_user_id) REFERENCES admin_users (id) ON DELETE CASCADE,
    CONSTRAINT uq_admin_sessions_token_hash UNIQUE (token_hash)
);

COMMENT ON COLUMN admin_sessions.token_hash IS 'SHA-256 hash of the session token; never the token.';

-- Resolve a presented session by its hash (hot path on every admin request).
CREATE INDEX ix_admin_sessions_token_hash ON admin_sessions (token_hash);
-- Sweep / "log out everywhere" by owner.
CREATE INDEX ix_admin_sessions_user ON admin_sessions (admin_user_id);
