package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.hg.grantmint.server.security.AdminUserService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

/**
 * The M11 browser auth contract (GRANTMINT-40/41): login sets an HttpOnly SameSite=Strict session
 * cookie; a cookie-authenticated state-changing request must double-submit the XSRF token and is
 * 403'd without it; bearer-authenticated calls (the CLI/API path) remain CSRF-exempt because a
 * browser can never send that header ambiently; logout revokes the session and expires the cookie.
 */
@SpringBootTest(properties = "grantmint.admin.session.cookie-secure=false")
@AutoConfigureMockMvc
@Transactional
class AdminCookieCsrfFlowIntegrationTest extends PostgresIntegrationTest {

    private static final String COOKIE = "gm_admin_session";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AdminUserService adminUsers;

    @BeforeEach
    void operator() {
        adminUsers.bootstrapIfEmpty("op-cookie", "correct horse battery");
    }

    @Test
    void loginSetsAnHttpOnlySameSiteStrictSessionCookie() throws Exception {
        MvcResult result = login();
        // Login can emit several Set-Cookie headers (the XSRF-TOKEN cookie rides along) —
        // find the session cookie among them.
        String setCookie = result.getResponse().getHeaders("Set-Cookie").stream()
                .filter(header -> header.startsWith(COOKIE + "="))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no session Set-Cookie header on login"));

        assertThat(setCookie).contains(COOKIE + "=gm_sess_");
        assertThat(setCookie).contains("HttpOnly");
        assertThat(setCookie).contains("SameSite=Strict");
        assertThat(setCookie).contains("Path=/");

        // The XSRF-TOKEN cookie's Secure attribute is pinned to the same cookie-secure property as
        // the session cookie (false in this test), not left to Spring's request.isSecure() default.
        String xsrfCookie = result.getResponse().getHeaders("Set-Cookie").stream()
                .filter(header -> header.startsWith("XSRF-TOKEN="))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no XSRF-TOKEN Set-Cookie header on login"));
        assertThat(xsrfCookie).doesNotContain("Secure");
        assertThat(setCookie).doesNotContain("Secure");
    }

    @Test
    void aCookieAuthenticatedReadWorksWithoutCsrfButAWriteDemandsTheToken() throws Exception {
        Cookie session = sessionCookieFrom(login());

        // Reads are never CSRF-protected.
        MvcResult read = mockMvc.perform(get("/admin/products").cookie(session))
                .andExpect(status().isOk())
                .andReturn();

        // A cookie-authenticated write without the XSRF header is exactly what CSRF forbids.
        mockMvc.perform(post("/admin/products")
                        .cookie(session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"csrf-blocked\",\"name\":\"Nope\"}"))
                .andExpect(status().isForbidden());

        // With the double-submitted token from the XSRF-TOKEN cookie, the same write succeeds.
        Cookie xsrf = read.getResponse().getCookie("XSRF-TOKEN");
        assertThat(xsrf).as("the SPA must be able to read an XSRF-TOKEN cookie").isNotNull();
        mockMvc.perform(post("/admin/products")
                        .cookie(session, xsrf)
                        .header("X-XSRF-TOKEN", xsrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"csrf-allowed\",\"name\":\"Yep\"}"))
                .andExpect(status().isCreated());
    }

    @Test
    void bearerAuthenticatedWritesStayCsrfExempt() throws Exception {
        String token = tokenFrom(login());

        mockMvc.perform(post("/admin/products")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"bearer-write\",\"name\":\"CLI\"}"))
                .andExpect(status().isCreated());
    }

    @Test
    void logoutRevokesTheSessionAndExpiresTheCookie() throws Exception {
        MvcResult loginResult = login();
        Cookie session = sessionCookieFrom(loginResult);
        Cookie xsrf = mockMvc.perform(get("/admin/products").cookie(session))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getCookie("XSRF-TOKEN");

        MvcResult logout = mockMvc.perform(
                        post("/admin/auth/logout").cookie(session, xsrf).header("X-XSRF-TOKEN", xsrf.getValue()))
                .andExpect(status().isNoContent())
                .andReturn();

        assertThat(logout.getResponse().getHeaders("Set-Cookie"))
                .anySatisfy(
                        header -> assertThat(header).startsWith(COOKIE + "=").contains("Max-Age=0"));
        mockMvc.perform(get("/admin/products").cookie(session)).andExpect(status().isUnauthorized());
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private MvcResult login() throws Exception {
        return mockMvc.perform(post("/admin/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"op-cookie\",\"password\":\"correct horse battery\"}"))
                .andExpect(status().isOk())
                .andReturn();
    }

    private static Cookie sessionCookieFrom(MvcResult result) {
        Cookie cookie = result.getResponse().getCookie(COOKIE);
        assertThat(cookie).isNotNull();
        return cookie;
    }

    private static String tokenFrom(MvcResult result) throws Exception {
        String body = result.getResponse().getContentAsString();
        int start = body.indexOf("\"token\":\"") + 9;
        return body.substring(start, body.indexOf('"', start));
    }
}
