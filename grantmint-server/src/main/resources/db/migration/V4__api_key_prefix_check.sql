-- Pin the api_keys.key_prefix length to the single canonical value the application produces.
--
-- ApiKeyGenerator.PREFIX_LENGTH is 12 (namespace + a peek of the random body), and every minted key's
-- plaintext is far longer than 12, so the stored prefix is always exactly 12 characters. The V1 inline
-- comment said "first 8 chars" — stale wording, never the actual behaviour. Rather than rewrite an
-- already-applied migration (which would change its checksum and break `flyway validate` on existing
-- deployments), this additive migration makes 12 authoritative in the schema itself. The check is the
-- source of truth; the V1 comment is superseded.
ALTER TABLE api_keys
    ADD CONSTRAINT ck_api_keys_prefix_len CHECK (char_length(key_prefix) = 12);
