package dev.hg.grantmint.server.it;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.grantmint.server.security.AdminUserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

/**
 * M13-audit hardening for {@code POST /admin/auth/password}: a session token alone must not be able
 * to rotate the credential — the current password is required — and a successful change revokes
 * every live session (credential rotation invalidates whatever a token thief was holding).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AdminPasswordChangeIntegrationTest extends PostgresIntegrationTest {

    private static final String ADMIN_USERNAME = "pwadmin";
    private static final String ADMIN_PASSWORD = "battery-staple-correct-horse";
    private static final String NEW_PASSWORD = "rotated-battery-staple";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AdminUserService adminUsers;

    @Autowired
    private ObjectMapper objectMapper;

    private String login(String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/admin/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + ADMIN_USERNAME + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper
                .readTree(result.getResponse().getContentAsString())
                .get("token")
                .asText();
    }

    @Test
    void sessionAloneCannotChangeThePassword() throws Exception {
        adminUsers.bootstrapIfEmpty(ADMIN_USERNAME, ADMIN_PASSWORD);
        String token = login(ADMIN_PASSWORD);

        // No currentPassword at all — the pre-hardening request shape — is refused.
        mockMvc.perform(post("/admin/auth/password")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"newPassword\":\"" + NEW_PASSWORD + "\"}"))
                .andExpect(status().isUnauthorized());

        // A wrong currentPassword is refused the same way.
        mockMvc.perform(post("/admin/auth/password")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"not-the-password\",\"newPassword\":\"" + NEW_PASSWORD + "\"}"))
                .andExpect(status().isUnauthorized());

        // The credential was not rotated and the session was not revoked by the failed attempts.
        mockMvc.perform(get("/admin/products").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        login(ADMIN_PASSWORD);
    }

    @Test
    void changingThePasswordRequiresTheCurrentOneAndRevokesAllSessions() throws Exception {
        adminUsers.bootstrapIfEmpty(ADMIN_USERNAME, ADMIN_PASSWORD);
        String firstSession = login(ADMIN_PASSWORD);
        String secondSession = login(ADMIN_PASSWORD);

        mockMvc.perform(post("/admin/auth/password")
                        .header("Authorization", "Bearer " + firstSession)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"" + ADMIN_PASSWORD + "\",\"newPassword\":\"" + NEW_PASSWORD
                                + "\"}"))
                .andExpect(status().isNoContent());

        // Every session is dead — including the one that made the change and the bystander.
        mockMvc.perform(get("/admin/products").header("Authorization", "Bearer " + firstSession))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/admin/products").header("Authorization", "Bearer " + secondSession))
                .andExpect(status().isUnauthorized());

        // The old password no longer authenticates; the new one does.
        mockMvc.perform(post("/admin/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + ADMIN_USERNAME + "\",\"password\":\"" + ADMIN_PASSWORD + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("unauthorized"));
        login(NEW_PASSWORD);
    }
}
