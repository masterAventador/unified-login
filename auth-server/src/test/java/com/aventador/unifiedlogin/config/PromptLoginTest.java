package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class PromptLoginTest {

    private static final String FIRST_USER = "prompt-login-first@example.com";
    private static final String SECOND_USER = "prompt-login-second@example.com";
    private static final String PASSWORD = "a valid password";
    private static final String STATE = "prompt-login-state";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @BeforeEach
    void createUsers() {
        if (!registrationService.isEmailTaken(FIRST_USER)) {
            registrationService.register(FIRST_USER, PASSWORD);
        }
        if (!registrationService.isEmailTaken(SECOND_USER)) {
            registrationService.register(SECOND_USER, PASSWORD);
        }
    }

    @Test
    void promptLoginForcesExistingSessionThroughLoginBeforeIssuingCode() throws Exception {
        MockHttpSession session = OAuth2TestFlows.login(mockMvc, FIRST_USER, PASSWORD);
        Map<String, String> params = OAuth2TestFlows.validAuthorizeParams();
        params.put("prompt", "login");
        params.put("state", STATE);
        String authorizeUri = OAuth2TestFlows.authorizeUri(params);

        mockMvc.perform(get(authorizeUri).session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));

        MvcResult login = mockMvc.perform(post("/login")
                        .session(session)
                        .with(csrf())
                        .param("username", SECOND_USER)
                        .param("password", PASSWORD))
                .andExpect(authenticated().withUsername(SECOND_USER))
                .andExpect(status().isFound())
                .andReturn();

        String savedAuthorizeUri = login.getResponse().getRedirectedUrl();
        assertThat(savedAuthorizeUri)
                .startsWith("http://localhost" + authorizeUri)
                .contains("&continue");

        MvcResult authorization = mockMvc.perform(get(savedAuthorizeUri).session(session))
                .andExpect(status().isFound())
                .andReturn();

        assertThat(authorization.getResponse().getRedirectedUrl())
                .startsWith(OAuth2TestFlows.REDIRECT_URI);
        assertThat(OAuth2TestFlows.queryParams(
                authorization.getResponse().getRedirectedUrl()))
                .containsKeys("code")
                .containsEntry("state", STATE)
                .doesNotContainKey("error");
    }
}
