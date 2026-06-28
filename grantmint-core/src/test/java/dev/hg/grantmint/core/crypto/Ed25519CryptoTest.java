package dev.hg.grantmint.core.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.EdECPublicKey;
import java.util.Arrays;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;
import org.junit.jupiter.api.Test;

class Ed25519CryptoTest {

    private static final SecureRandom RNG = new SecureRandom();

    @Test
    void signAndVerifyRoundTrip() {
        KeyPair kp = Ed25519Keys.generate(RNG);
        Ed25519Signer signer = new Ed25519Signer(kp.getPrivate(), "K1");
        Ed25519Verifier verifier = new Ed25519Verifier(kp.getPublic());

        byte[] message = "the quick brown fox".getBytes();
        byte[] signature = signer.sign(message);

        assertThat(signature).hasSize(64);
        assertThat(verifier.verify(message, signature)).isTrue();
    }

    @Test
    void verifyRejectsTamperedMessage() {
        KeyPair kp = Ed25519Keys.generate(RNG);
        Ed25519Signer signer = new Ed25519Signer(kp.getPrivate(), "K1");
        Ed25519Verifier verifier = new Ed25519Verifier(kp.getPublic());

        byte[] message = "authentic".getBytes();
        byte[] signature = signer.sign(message);

        assertThat(verifier.verify("tampered!".getBytes(), signature)).isFalse();
    }

    @Test
    void verifyRejectsWrongLengthSignatureWithoutThrowing() {
        KeyPair kp = Ed25519Keys.generate(RNG);
        Ed25519Verifier verifier = new Ed25519Verifier(kp.getPublic());
        assertThat(verifier.verify("msg".getBytes(), new byte[] {1, 2, 3})).isFalse();
    }

    @Test
    void rawKeyLengthsAre32() {
        KeyPair kp = Ed25519Keys.generate(RNG);
        assertThat(Ed25519Keys.encodePublicKey(kp.getPublic())).hasSize(32);
        assertThat(Ed25519Keys.encodePrivateKey(kp.getPrivate())).hasSize(32);
    }

    @Test
    void decodeRejectsWrongLength() {
        assertThatThrownBy(() -> Ed25519Keys.decodePublicKey(new byte[31]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** Raw public-key export/import must be byte-exact — clients embed and reload these 32 bytes. */
    @Property(tries = 200)
    void publicKeyRawRoundTrip(@ForAll @Size(8) byte[] ignoredSeedForVariation) {
        KeyPair kp = Ed25519Keys.generate(RNG);
        byte[] raw = Ed25519Keys.encodePublicKey(kp.getPublic());
        var reloaded = Ed25519Keys.decodePublicKey(raw);

        assertThat(Ed25519Keys.encodePublicKey(reloaded)).isEqualTo(raw);
        // And the reloaded key still verifies a signature from the original private key.
        byte[] sig = new Ed25519Signer(kp.getPrivate(), "K1").sign(raw);
        assertThat(new Ed25519Verifier(reloaded).verify(raw, sig)).isTrue();
        assertThat(reloaded).isInstanceOf(EdECPublicKey.class);
    }

    /** Raw private-seed export/import must reproduce a functioning, identical signing key. */
    @Property(tries = 200)
    void privateKeyRawRoundTrip(@ForAll @Size(8) byte[] ignoredSeedForVariation) {
        KeyPair kp = Ed25519Keys.generate(RNG);
        byte[] seed = Ed25519Keys.encodePrivateKey(kp.getPrivate());
        var reloaded = Ed25519Keys.decodePrivateKey(seed);

        assertThat(Ed25519Keys.encodePrivateKey(reloaded)).isEqualTo(seed);
        byte[] message = "round-trip".getBytes();
        byte[] sigOriginal = new Ed25519Signer(kp.getPrivate(), "K1").sign(message);
        byte[] sigReloaded = new Ed25519Signer(reloaded, "K1").sign(message);
        // Ed25519 is deterministic, so the same seed yields the same signature.
        assertThat(Arrays.equals(sigOriginal, sigReloaded)).isTrue();
    }
}
