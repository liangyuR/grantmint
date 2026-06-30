package dev.hg.grantmint.server.it;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Verifies the OpenAPI access-control knob actually enforces: with {@code
 * grantmint.openapi.access=admin}, the doc and Swagger UI endpoints require an admin session — an
 * unauthenticated request is rejected, not served. This is the remediation for the audit finding that
 * the doc endpoints bypassed all security with no way to lock them down.
 */
@SpringBootTest(properties = "grantmint.openapi.access=admin")
@AutoConfigureMockMvc
class OpenApiDocsAdminAccessTest extends PostgresIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void apiDocsRequiresAdminWhenLockedDown() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/v3/api-docs")).andExpect(status().isUnauthorized());
    }

    @Test
    void swaggerUiRequiresAdminWhenLockedDown() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/swagger-ui/index.html")).andExpect(status().isUnauthorized());
    }
}
