package dev.hg.grantmint.core.crypto;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.EdECPublicKey;
import java.util.Base64;
import java.util.Objects;

/**
 * Verifies Ed25519 signatures over raw message bytes using only the public key.
 *
 * <p>This is the safe-to-ship half of the pair: a verifier can confirm a signature was produced by
 * the matching {@link Ed25519Signer} but can never mint one. Clients embed the raw 32-byte public
 * key at build time and construct a verifier with {@link #fromRaw(byte[])} / {@link
 * #fromBase64(String)}.
 *
 * <p>{@link #verify(byte[], byte[])} returns {@code false} for any tampered, forged, or malformed
 * signature rather than throwing — verification is a boolean decision, not an exceptional one. Only
 * a broken JVM (no Ed25519 provider) raises {@link CryptoException}.
 */
public final class Ed25519Verifier {

    private static final String ALGORITHM = "Ed25519";

    private final PublicKey publicKey;

    public Ed25519Verifier(PublicKey publicKey) {
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey");
        // The JDK reports these keys' algorithm as "EdDSA"; check the concrete type instead.
        if (!(publicKey instanceof EdECPublicKey)) {
            throw new IllegalArgumentException("Not an Ed25519 public key: " + publicKey.getAlgorithm());
        }
    }

    /** Build a verifier from a raw 32-byte RFC 8032 public key. */
    public static Ed25519Verifier fromRaw(byte[] rawPublicKey) {
        return new Ed25519Verifier(Ed25519Keys.decodePublicKey(rawPublicKey));
    }

    /** Build a verifier from a standard-Base64 encoding of the raw 32-byte public key. */
    public static Ed25519Verifier fromBase64(String base64RawPublicKey) {
        Objects.requireNonNull(base64RawPublicKey, "base64RawPublicKey");
        return fromRaw(Base64.getDecoder().decode(base64RawPublicKey));
    }

    /** The underlying public key. */
    public PublicKey publicKey() {
        return publicKey;
    }

    /**
     * Verify {@code signature} over {@code message}.
     *
     * @return {@code true} only if the signature is authentic; {@code false} for any tampering,
     *     forgery, or structurally invalid signature.
     */
    public boolean verify(byte[] message, byte[] signature) {
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(signature, "signature");
        try {
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (java.security.SignatureException e) {
            // Malformed signature bytes (e.g. wrong length) — not authentic, but not a JVM fault.
            return false;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Ed25519 verification failed", e);
        }
    }
}
