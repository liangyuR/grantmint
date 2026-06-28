package dev.hg.grantmint.core.crypto;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.EdECPrivateKey;
import java.util.Objects;

/**
 * Produces Ed25519 signatures over raw message bytes — the server-side crown jewel.
 *
 * <p>A signer pairs an Ed25519 {@link PrivateKey} with the short <em>signing-key id</em> that
 * identifies which key pair signed (written into the token header's {@code kid} so a verifier can
 * pick the matching embedded public key after rotation). The private key is held in memory only and
 * is never logged, serialized, or exposed by this class.
 *
 * <p>Instances are immutable and thread-safe; each {@link #sign(byte[])} creates its own
 * {@link Signature} object.
 */
public final class Ed25519Signer {

    private static final String ALGORITHM = "Ed25519";

    private final PrivateKey privateKey;
    private final String signingKeyId;

    public Ed25519Signer(PrivateKey privateKey, String signingKeyId) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        this.signingKeyId = Objects.requireNonNull(signingKeyId, "signingKeyId");
        // The JDK reports these keys' algorithm as "EdDSA"; check the concrete type instead.
        if (!(privateKey instanceof EdECPrivateKey)) {
            throw new IllegalArgumentException("Not an Ed25519 private key: " + privateKey.getAlgorithm());
        }
    }

    /** Build a signer from a raw 32-byte seed and a signing-key id. */
    public static Ed25519Signer fromRawSeed(byte[] seed, String signingKeyId) {
        return new Ed25519Signer(Ed25519Keys.decodePrivateKey(seed), signingKeyId);
    }

    /** The signing-key id this signer stamps into token headers. */
    public String signingKeyId() {
        return signingKeyId;
    }

    /** Sign {@code message}, returning the 64-byte Ed25519 signature. */
    public byte[] sign(byte[] message) {
        Objects.requireNonNull(message, "message");
        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initSign(privateKey);
            signature.update(message);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Ed25519 signing failed", e);
        }
    }
}
