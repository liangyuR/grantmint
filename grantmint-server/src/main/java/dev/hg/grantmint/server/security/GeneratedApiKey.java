package dev.hg.grantmint.server.security;

/**
 * The result of minting an API key. The {@code plaintext} is the only time the full secret exists
 * outside the caller's request — it is returned once and never persisted. Only {@code keyHash} and
 * {@code keyPrefix} are stored.
 *
 * @param plaintext the full secret, e.g. {@code gm_live_7f3a…}; show once, then discard
 * @param keyHash SHA-256 hex of the plaintext, persisted in {@code api_keys.key_hash}
 * @param keyPrefix human-friendly leading slice for display, persisted in {@code api_keys.key_prefix}
 */
public record GeneratedApiKey(String plaintext, String keyHash, String keyPrefix) {}
