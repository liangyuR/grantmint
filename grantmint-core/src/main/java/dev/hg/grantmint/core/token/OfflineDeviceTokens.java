package dev.hg.grantmint.core.token;

import dev.hg.grantmint.core.codec.Base64Url;
import dev.hg.grantmint.core.codec.CanonicalJson;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public final class OfflineDeviceTokens {
    private OfflineDeviceTokens() {}

    public static String sign(Ed25519Signer signer, String type, Map<String, Object> claims) {
        String header = Base64Url.encode(CanonicalJson.serialize(
                Map.of("alg", "EdDSA", "crv", "Ed25519", "typ", type, "kid", signer.signingKeyId())));
        String payload = Base64Url.encode(CanonicalJson.serialize(claims));
        String message = header + "." + payload;
        return message + "." + Base64Url.encode(signer.sign(message.getBytes(StandardCharsets.US_ASCII)));
    }

    public static String keyHash(byte[] publicKey) {
        try {
            return Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(publicKey));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] activationMessage(
            String challengeId,
            String nonce,
            String productId,
            String licenseId,
            String devicePublicKey,
            String fingerprintHash,
            int fingerprintVersion) {
        return String.join(
                        "\n",
                        "grantmint.activate.v2",
                        challengeId,
                        nonce,
                        productId,
                        licenseId,
                        devicePublicKey,
                        fingerprintHash,
                        Integer.toString(fingerprintVersion))
                .getBytes(StandardCharsets.UTF_8);
    }
}
