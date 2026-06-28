package dev.hg.grantmint.server.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.core.crypto.Ed25519Signer;
import dev.hg.grantmint.core.crypto.Ed25519Verifier;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.domain.SigningKey;
import dev.hg.grantmint.server.repo.ProductRepository;
import dev.hg.grantmint.server.repo.SigningKeyRepository;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Signing-key registration and signer minting. Backed by a real Ed25519 keypair and an
 * env-backed resolver so the trust-anchor invariants are exercised end to end: the public key is
 * provably matched before persistence, the private bytes never reach the entity, and a minted
 * signer produces signatures the stored public key verifies.
 */
@ExtendWith(MockitoExtension.class)
class SigningKeyServiceTest {

    private static final String KEY_ID = "ed25519-2026-01";
    private static final UUID PRODUCT_ID = UUID.randomUUID();

    @Mock
    private SigningKeyRepository signingKeys;

    @Mock
    private ProductRepository products;

    private KeyPair keyPair;
    private byte[] publicKey;
    private String ref;
    private SigningKeyService service;

    @BeforeEach
    void setUp() {
        keyPair = Ed25519Keys.generate(new SecureRandom());
        publicKey = Ed25519Keys.encodePublicKey(keyPair.getPublic());
        byte[] seed = Ed25519Keys.encodePrivateKey(keyPair.getPrivate());
        ref = "env:GM_TEST_SEED";
        PrivateKeySeedResolver resolver = new PrivateKeySeedResolver(
                name -> "GM_TEST_SEED".equals(name) ? HexFormat.of().formatHex(seed) : null);
        service = new SigningKeyService(signingKeys, products, resolver);
    }

    @Test
    void registersPublicKeyAndPointerWithoutPersistingPrivateBytes() {
        Product product = new Product();
        when(products.findById(PRODUCT_ID)).thenReturn(Optional.of(product));
        when(signingKeys.save(any(SigningKey.class))).thenAnswer(inv -> inv.getArgument(0));

        service.register(PRODUCT_ID, KEY_ID, ref, publicKey, true);

        ArgumentCaptor<SigningKey> captor = ArgumentCaptor.forClass(SigningKey.class);
        verify(signingKeys).save(captor.capture());
        SigningKey saved = captor.getValue();
        assertThat(saved.getKeyId()).isEqualTo(KEY_ID);
        assertThat(saved.getPublicKey()).containsExactly(publicKey);
        assertThat(saved.getPrivateKeyRef()).isEqualTo(ref); // pointer, not bytes
        assertThat(saved.getAlgorithm()).isEqualTo("Ed25519");
        assertThat(product.getActiveSigningKeyId()).isEqualTo(KEY_ID);
        verify(products).save(product);
    }

    @Test
    void doesNotActivateWhenMakeActiveFalse() {
        Product product = new Product();
        when(products.findById(PRODUCT_ID)).thenReturn(Optional.of(product));
        when(signingKeys.save(any(SigningKey.class))).thenAnswer(inv -> inv.getArgument(0));

        service.register(PRODUCT_ID, KEY_ID, ref, publicKey, false);

        assertThat(product.getActiveSigningKeyId()).isNull();
        verify(products, never()).save(any());
    }

    @Test
    void rejectsMismatchedPublicKeyBeforePersisting() {
        Product product = new Product();
        when(products.findById(PRODUCT_ID)).thenReturn(Optional.of(product));
        byte[] otherPublic = Ed25519Keys.encodePublicKey(
                Ed25519Keys.generate(new SecureRandom()).getPublic());

        assertThatThrownBy(() -> service.register(PRODUCT_ID, KEY_ID, ref, otherPublic, true))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("does not match");
        verify(signingKeys, never()).save(any());
    }

    @Test
    void rejectsWrongLengthPublicKey() {
        // The length guard fires before the product lookup, so no repository stub is needed.
        assertThatThrownBy(() -> service.register(PRODUCT_ID, KEY_ID, ref, new byte[16], true))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    void registerFailsForUnknownProduct() {
        when(products.findById(PRODUCT_ID)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.register(PRODUCT_ID, KEY_ID, ref, publicKey, true))
                .isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void signerForKeyIdProducesVerifiableSignatures() {
        when(signingKeys.findById(KEY_ID)).thenReturn(Optional.of(activeKey()));

        Ed25519Signer signer = service.signerForKeyId(KEY_ID);
        byte[] message = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] signature = signer.sign(message);

        assertThat(signer.signingKeyId()).isEqualTo(KEY_ID);
        assertThat(Ed25519Verifier.fromRaw(publicKey).verify(message, signature))
                .isTrue();
    }

    @Test
    void signerForProductResolvesActiveKey() {
        Product product = new Product();
        product.setActiveSigningKeyId(KEY_ID);
        when(products.findById(PRODUCT_ID)).thenReturn(Optional.of(product));
        when(signingKeys.findById(KEY_ID)).thenReturn(Optional.of(activeKey()));

        assertThat(service.signerForProduct(PRODUCT_ID).signingKeyId()).isEqualTo(KEY_ID);
    }

    @Test
    void signerForProductFailsWhenNoActiveKey() {
        when(products.findById(PRODUCT_ID)).thenReturn(Optional.of(new Product()));
        assertThatThrownBy(() -> service.signerForProduct(PRODUCT_ID))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("no active signing key");
    }

    @Test
    void signerForKeyIdRejectsRetiredKey() {
        SigningKey retired = activeKey();
        retired.setStatus("retired");
        when(signingKeys.findById(KEY_ID)).thenReturn(Optional.of(retired));
        assertThatThrownBy(() -> service.signerForKeyId(KEY_ID))
                .isInstanceOf(SigningKeyException.class)
                .hasMessageContaining("not active");
    }

    private SigningKey activeKey() {
        SigningKey key = new SigningKey();
        key.setKeyId(KEY_ID);
        key.setPublicKey(publicKey);
        key.setPrivateKeyRef(ref);
        key.setStatus("active");
        return key;
    }
}
