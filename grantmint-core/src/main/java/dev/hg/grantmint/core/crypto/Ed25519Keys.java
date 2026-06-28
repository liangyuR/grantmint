package dev.hg.grantmint.core.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * Ed25519 key generation and the raw 32-byte key encodings clients ship with.
 *
 * <p>The JDK speaks Ed25519 keys as JCA {@link PublicKey}/{@link PrivateKey} objects, but every
 * other ecosystem (Apple CryptoKit, Go's {@code crypto/ed25519}, the bytes a verifier embeds at
 * build time) speaks <strong>raw 32-byte</strong> keys per RFC 8032. This class is the bridge:
 * generation plus byte-exact import/export so a public key minted here verifies a token identically
 * in Java, Swift, and Go. The encodings are part of the security contract — see
 * docs/features/LICENSE_TOKEN_FORMAT.md and docs/features/CLIENT_SDK.md.
 *
 * <ul>
 *   <li><b>Public key</b> — the y-coordinate as a 255-bit little-endian integer, with the most
 *       significant bit of byte 31 carrying the sign of x (RFC 8032 §5.1.2).
 *   <li><b>Private key</b> — the 32-byte seed (RFC 8032 §5.1.5), <em>not</em> the expanded scalar.
 * </ul>
 */
public final class Ed25519Keys {

    /** Raw Ed25519 keys are exactly 32 bytes (the seed for private, the compressed point for public). */
    public static final int RAW_KEY_LENGTH = 32;

    private static final String ALGORITHM = "Ed25519";

    private Ed25519Keys() {}

    /** Generate a fresh Ed25519 key pair from the supplied randomness source. */
    public static KeyPair generate(SecureRandom random) {
        Objects.requireNonNull(random, "random");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
            generator.initialize(NamedParameterSpec.ED25519, random);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Ed25519 key generation failed", e);
        }
    }

    /** Export a public key as its raw 32-byte RFC 8032 encoding. */
    public static byte[] encodePublicKey(PublicKey publicKey) {
        if (!(publicKey instanceof EdECPublicKey edKey)) {
            throw new IllegalArgumentException("Not an Ed25519 public key: " + publicKey.getAlgorithm());
        }
        EdECPoint point = edKey.getPoint();
        byte[] raw = toLittleEndian(point.getY());
        if (point.isXOdd()) {
            raw[RAW_KEY_LENGTH - 1] |= (byte) 0x80;
        }
        return raw;
    }

    /** Reconstruct a public key from its raw 32-byte RFC 8032 encoding. */
    public static PublicKey decodePublicKey(byte[] raw) {
        requireRawLength(raw);
        byte[] copy = raw.clone();
        boolean xOdd = (copy[RAW_KEY_LENGTH - 1] & 0x80) != 0;
        copy[RAW_KEY_LENGTH - 1] &= (byte) 0x7f;
        BigInteger y = fromLittleEndian(copy);
        EdECPoint point = new EdECPoint(xOdd, y);
        try {
            return KeyFactory.getInstance(ALGORITHM)
                    .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, point));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Invalid raw Ed25519 public key", e);
        }
    }

    /** Export a private key as its raw 32-byte seed. */
    public static byte[] encodePrivateKey(PrivateKey privateKey) {
        if (!(privateKey instanceof EdECPrivateKey edKey)) {
            throw new IllegalArgumentException("Not an Ed25519 private key: " + privateKey.getAlgorithm());
        }
        return edKey.getBytes()
                .orElseThrow(() -> new CryptoException("Ed25519 private key seed is not extractable", null));
    }

    /** Reconstruct a private key from its raw 32-byte seed. */
    public static PrivateKey decodePrivateKey(byte[] seed) {
        requireRawLength(seed);
        try {
            return KeyFactory.getInstance(ALGORITHM)
                    .generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed.clone()));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Invalid raw Ed25519 private key seed", e);
        }
    }

    private static void requireRawLength(byte[] raw) {
        Objects.requireNonNull(raw, "raw");
        if (raw.length != RAW_KEY_LENGTH) {
            throw new IllegalArgumentException(
                    "Raw Ed25519 key must be " + RAW_KEY_LENGTH + " bytes, was " + raw.length);
        }
    }

    /** Big-endian, non-negative {@link BigInteger} (y &lt; 2^255) to a fixed 32-byte little-endian array. */
    private static byte[] toLittleEndian(BigInteger value) {
        byte[] be = value.toByteArray(); // big-endian, two's complement, maybe a leading 0x00 sign byte
        byte[] le = new byte[RAW_KEY_LENGTH];
        for (int i = 0; i < be.length && i < RAW_KEY_LENGTH; i++) {
            le[i] = be[be.length - 1 - i];
        }
        return le;
    }

    /** Fixed 32-byte little-endian array to a non-negative {@link BigInteger}. */
    private static BigInteger fromLittleEndian(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) {
            be[i] = le[le.length - 1 - i];
        }
        return new BigInteger(1, be);
    }

    /** Constant-time comparison for raw key/signature material. */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return java.security.MessageDigest.isEqual(a, b);
    }

    /** Defensive copy helper kept out of callers' way. */
    static byte[] copyOf(byte[] value) {
        return Arrays.copyOf(value, value.length);
    }
}
