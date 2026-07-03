package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.grantmint.core.crypto.Ed25519Keys;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.repo.ProductRepository;
import dev.hg.grantmint.server.security.AdminUserService;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

/**
 * Integration tests for the admin signing-key endpoints (GRANTMINT-118). Exercises the full Spring
 * stack — real PostgreSQL, real {@code PrivateKeySeedResolver} dereferencing a {@code file:} ref —
 * so the trust-anchor invariant is verified end to end over HTTP: registration proves the supplied
 * public key matches the private seed before persisting, private bytes never appear in a response,
 * and {@code makeActive} flips the product's active signing key.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@EnabledOnOs({OS.LINUX, OS.MAC})
class SigningKeyAdminIntegrationTest extends PostgresIntegrationTest {

    private static final String ADMIN_USERNAME = "signingkeyadmin";
    private static final String ADMIN_PASSWORD = "battery-staple-correct-horse"; // gitleaks:allow

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AdminUserService adminUsers;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ProductRepository productRepo;

    @TempDir
    private Path tempDir;

    private String adminSessionToken() throws Exception {
        adminUsers.bootstrapIfEmpty(ADMIN_USERNAME, ADMIN_PASSWORD);
        MvcResult result = mockMvc.perform(post("/admin/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + ADMIN_USERNAME + "\",\"password\":\"" + ADMIN_PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andReturn();
        return objectMapper
                .readTree(result.getResponse().getContentAsString())
                .get("token")
                .asText();
    }

    private UUID createProduct(String token, String slug) throws Exception {
        MvcResult result = mockMvc.perform(post("/admin/products")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"" + slug + "\",\"name\":\"" + slug + "\",\"description\":\"test\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        return UUID.fromString(objectMapper
                .readTree(result.getResponse().getContentAsString())
                .get("id")
                .asText());
    }

    /** Writes a fresh Ed25519 seed to an owner-only-readable file and returns its {@code file:} ref. */
    private String seedRef(String fileName, byte[] seed) throws IOException {
        Path file = tempDir.resolve(fileName);
        Files.writeString(file, HexFormat.of().formatHex(seed), StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        return "file:" + file;
    }

    @Test
    void unauthenticatedRequestIs401() throws Exception {
        mockMvc.perform(get("/admin/products/" + UUID.randomUUID() + "/signing-keys"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void registersListsAndActivatesSigningKey() throws Exception {
        String token = adminSessionToken();
        UUID productId = createProduct(token, "signing-key-happy");

        KeyPair pair = Ed25519Keys.generate(new SecureRandom());
        byte[] publicKey = Ed25519Keys.encodePublicKey(pair.getPublic());
        byte[] seed = Ed25519Keys.encodePrivateKey(pair.getPrivate());
        String ref = seedRef("seed-happy.hex", seed);
        String publicKeyB64 = Base64.getEncoder().encodeToString(publicKey);

        MvcResult registerResult = mockMvc.perform(post("/admin/products/" + productId + "/signing-keys")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyId\":\"ed25519-2026-01\",\"privateKeyRef\":\"" + escape(ref)
                                + "\",\"publicKey\":\"" + publicKeyB64 + "\",\"makeActive\":true}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.keyId").value("ed25519-2026-01"))
                .andExpect(jsonPath("$.productId").value(productId.toString()))
                .andExpect(jsonPath("$.algorithm").value("Ed25519"))
                .andExpect(jsonPath("$.publicKey").value(publicKeyB64))
                .andExpect(jsonPath("$.privateKeyRef").value(ref))
                .andExpect(jsonPath("$.status").value("active"))
                .andReturn();
        // Note: createdAt is populated by Hibernate's @CreationTimestamp at flush time, so it is
        // not yet visible on the entity instance returned by the same-transaction create call
        // (see Product's createdAt, which exhibits the same behavior); the JSON shape still carries
        // the field.
        assertThat(registerResult.getResponse().getContentAsString())
                .doesNotContain(HexFormat.of().formatHex(seed));

        // makeActive:true flips the product's active signing key.
        Product product = productRepo.findById(productId).orElseThrow();
        assertThat(product.getActiveSigningKeyId()).isEqualTo("ed25519-2026-01");

        // List returns the registered key.
        mockMvc.perform(get("/admin/products/" + productId + "/signing-keys")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].keyId").value("ed25519-2026-01"))
                .andExpect(jsonPath("$[0].publicKey").value(publicKeyB64))
                .andExpect(jsonPath("$[0].status").value("active"));
    }

    @Test
    void secondKeyWithMakeActiveFalseDoesNotChangeActiveKey() throws Exception {
        String token = adminSessionToken();
        UUID productId = createProduct(token, "signing-key-inactive");

        KeyPair first = Ed25519Keys.generate(new SecureRandom());
        String firstRef = seedRef("seed-first.hex", Ed25519Keys.encodePrivateKey(first.getPrivate()));
        mockMvc.perform(post("/admin/products/" + productId + "/signing-keys")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyId\":\"key-a\",\"privateKeyRef\":\"" + escape(firstRef) + "\",\"publicKey\":\""
                                + Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(first.getPublic()))
                                + "\",\"makeActive\":true}"))
                .andExpect(status().isCreated());

        KeyPair second = Ed25519Keys.generate(new SecureRandom());
        String secondRef = seedRef("seed-second.hex", Ed25519Keys.encodePrivateKey(second.getPrivate()));
        mockMvc.perform(post("/admin/products/" + productId + "/signing-keys")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyId\":\"key-b\",\"privateKeyRef\":\"" + escape(secondRef) + "\",\"publicKey\":\""
                                + Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(second.getPublic()))
                                + "\",\"makeActive\":false}"))
                .andExpect(status().isCreated());

        assertThat(productRepo.findById(productId).orElseThrow().getActiveSigningKeyId())
                .isEqualTo("key-a");

        mockMvc.perform(get("/admin/products/" + productId + "/signing-keys")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2));
    }

    @Test
    void badBase64PublicKeyIs400() throws Exception {
        String token = adminSessionToken();
        UUID productId = createProduct(token, "signing-key-badb64"); // gitleaks:allow — product slug, not a key
        KeyPair pair = Ed25519Keys.generate(new SecureRandom());
        String ref = seedRef("seed-badb64.hex", Ed25519Keys.encodePrivateKey(pair.getPrivate()));

        mockMvc.perform(post("/admin/products/" + productId + "/signing-keys")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyId\":\"key-bad\",\"privateKeyRef\":\"" + escape(ref)
                                + "\",\"publicKey\":\"not-valid-base64!!\",\"makeActive\":false}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void wrongLengthPublicKeyIs400() throws Exception {
        String token = adminSessionToken();
        UUID productId = createProduct(token, "signing-key-badlen");
        KeyPair pair = Ed25519Keys.generate(new SecureRandom());
        String ref = seedRef("seed-badlen.hex", Ed25519Keys.encodePrivateKey(pair.getPrivate()));
        String shortKeyB64 = Base64.getEncoder().encodeToString(new byte[16]);

        mockMvc.perform(post("/admin/products/" + productId + "/signing-keys")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyId\":\"key-short\",\"privateKeyRef\":\"" + escape(ref) + "\",\"publicKey\":\""
                                + shortKeyB64 + "\",\"makeActive\":false}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void mismatchedPublicKeyIs400() throws Exception {
        String token = adminSessionToken();
        UUID productId = createProduct(token, "signing-key-mismatch");

        KeyPair actual = Ed25519Keys.generate(new SecureRandom());
        String ref = seedRef("seed-mismatch.hex", Ed25519Keys.encodePrivateKey(actual.getPrivate()));
        KeyPair other = Ed25519Keys.generate(new SecureRandom());
        String otherPublicB64 = Base64.getEncoder().encodeToString(Ed25519Keys.encodePublicKey(other.getPublic()));

        mockMvc.perform(post("/admin/products/" + productId + "/signing-keys")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyId\":\"key-mismatch\",\"privateKeyRef\":\"" + escape(ref)
                                + "\",\"publicKey\":\"" + otherPublicB64 + "\",\"makeActive\":false}"))
                .andExpect(status().isBadRequest());
    }

    /** Escapes backslashes so a Windows-style/temp path survives round-tripping through JSON literal content. */
    private static String escape(String value) {
        return value.replace("\\", "\\\\");
    }
}
