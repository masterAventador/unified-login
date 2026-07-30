package com.aventador.unifiedlogin.admin;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import({PostgresTestConfig.class, PlatformAdminGuardTest.AdminProbeController.class})
class PlatformAdminGuardTest {

    private static final String PASSWORD = "a valid password";

    private static final String ADMIN_RESPONSE = "platform-admin-only";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void ordinaryUserBearerTokenIsForbiddenWithoutResponseLeakage() throws Exception {
        String accessToken = issueAccessToken("ordinary-admin-probe@example.com");

        mockMvc.perform(get("/admin/probe")
                        .header("Authorization", "Bearer " + accessToken)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden())
                .andExpect(content().string(not(containsString(ADMIN_RESPONSE))));
    }

    @Test
    void platformAdminBearerTokenCanAccessAdminRoutes() throws Exception {
        String email = "platform-admin-probe@example.com";
        registrationService.register(email, PASSWORD);
        assertThat(jdbcTemplate.update(
                "UPDATE app_user SET is_platform_admin = true WHERE email = ?", email))
                .isEqualTo(1);
        String accessToken = issueAccessTokenForExistingUser(email);

        mockMvc.perform(get("/admin/probe")
                        .header("Authorization", "Bearer " + accessToken)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string(ADMIN_RESPONSE));
    }

    @Test
    void anonymousRequestCannotSeeAdminResponse() throws Exception {
        mockMvc.perform(get("/admin/probe").accept(MediaType.APPLICATION_JSON))
                .andExpect((result) -> assertThat(result.getResponse().getStatus())
                        .isIn(401, 302))
                .andExpect(content().string(not(containsString(ADMIN_RESPONSE))));
    }

    @Test
    void formLoginSessionCannotReplaceAdminApiBearerToken() throws Exception {
        String email = "session-platform-admin-probe@example.com";
        registrationService.register(email, PASSWORD);
        assertThat(jdbcTemplate.update(
                "UPDATE app_user SET is_platform_admin = true WHERE email = ?", email))
                .isEqualTo(1);
        MockHttpSession session = OAuth2TestFlows.login(mockMvc, email, PASSWORD);

        mockMvc.perform(get("/admin/probe")
                        .session(session)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden())
                .andExpect(content().string(not(containsString(ADMIN_RESPONSE))));
    }

    private String issueAccessToken(String email) throws Exception {
        registrationService.register(email, PASSWORD);
        return issueAccessTokenForExistingUser(email);
    }

    private String issueAccessTokenForExistingUser(String email) throws Exception {
        String tokenResponse = OAuth2TestFlows.exchangeCode(
                mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(
                        mockMvc,
                        OAuth2TestFlows.login(mockMvc, email, PASSWORD)));
        return OAuth2TestFlows.jsonField(tokenResponse, "access_token");
    }

    @RestController
    static class AdminProbeController {

        @GetMapping("/admin/probe")
        String probe() {
            return ADMIN_RESPONSE;
        }
    }
}
