package dev.hg.grantmint.server.it;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Verifies the OpenAPI surface is actually wired: springdoc generates the document from the
 * controllers, the {@link dev.hg.grantmint.server.api.OpenApiConfig} metadata (title + the three
 * security schemes) is present, and the doc/UI endpoints are reachable under the default access policy
 * ({@code grantmint.openapi.access=public}). The admin-locked-down variant is covered by
 * {@link OpenApiDocsAdminAccessTest}.
 */
@SpringBootTest
@AutoConfigureMockMvc
class OpenApiDocIntegrationTest extends PostgresIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void apiDocsIsGeneratedAndPublic() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.info.title").value("Grantmint API"))
                // All three auth schemes declared.
                .andExpect(jsonPath("$.components.securitySchemes.adminSession").exists())
                .andExpect(jsonPath("$.components.securitySchemes.issuanceKey").exists())
                .andExpect(jsonPath("$.components.securitySchemes.validationKey.name")
                        .value("X-Grantmint-Validation"))
                // The issuance operation is documented and references the issuance key.
                .andExpect(
                        jsonPath("$.paths['/issuance/licenses'].post.summary").value("Issue a license"))
                .andExpect(jsonPath("$.paths['/issuance/licenses'].post.security[0].issuanceKey")
                        .exists());
    }

    @Test
    void swaggerUiIsReachable() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/swagger-ui/index.html")).andExpect(status().isOk());
    }
}
