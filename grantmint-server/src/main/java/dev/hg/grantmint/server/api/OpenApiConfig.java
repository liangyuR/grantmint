package dev.hg.grantmint.server.api;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI 3 document metadata for the Grantmint REST API, served at {@code /v3/api-docs} with Swagger
 * UI at {@code /swagger-ui.html} (springdoc). The operation list and DTO schemas are generated from
 * the controllers; this class supplies the title/license and declares the three authentication
 * schemes so each endpoint can reference the one that guards it. See
 * docs/features/ADMIN_AND_API_AUTH.md.
 */
@Configuration
public class OpenApiConfig {

    /** OpenAPI security-scheme name for Scheme 1 (admin/dashboard session bearer). */
    public static final String ADMIN_SESSION = "adminSession";
    /** OpenAPI security-scheme name for Scheme 2 (per-product issuance key bearer). */
    public static final String ISSUANCE_KEY = "issuanceKey";
    /** OpenAPI security-scheme name for Scheme 3 (license-validation key header). */
    public static final String VALIDATION_KEY = "validationKey";

    @Bean
    OpenAPI grantmintOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("Grantmint API")
                        .version("0.1.0")
                        .description("Self-hostable license & entitlement server. Three isolated auth schemes: "
                                + "admin sessions manage everything; a per-product issuance key mints licenses; "
                                + "a low-privilege validation key is used by client apps. Grantmint consumes "
                                + "billing webhooks but never handles money.")
                        .license(new License().name("AGPL-3.0-only").url("https://www.gnu.org/licenses/agpl-3.0.txt")))
                .components(new Components()
                        .addSecuritySchemes(
                                ADMIN_SESSION,
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .description("Scheme 1 — admin session. `Authorization: Bearer gm_sess_…`, "
                                                + "obtained from POST /admin/auth/login."))
                        .addSecuritySchemes(
                                ISSUANCE_KEY,
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .description("Scheme 2 — per-product issuance key. "
                                                + "`Authorization: Bearer gm_live_…` (or gm_test_…)."))
                        .addSecuritySchemes(
                                VALIDATION_KEY,
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.APIKEY)
                                        .in(SecurityScheme.In.HEADER)
                                        .name("X-Grantmint-Validation")
                                        .description("Scheme 3 — low-privilege validation key (`gm_val_…`), "
                                                + "rate-limited; for validate/activate/heartbeat in the field.")));
    }
}
