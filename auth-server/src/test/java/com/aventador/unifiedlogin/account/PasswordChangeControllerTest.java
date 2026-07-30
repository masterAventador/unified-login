package com.aventador.unifiedlogin.account;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.security.LoginRateLimitProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class PasswordChangeControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private LoginRateLimitProperties rateLimitProperties;

    @Test
    void anonymousUserIsRedirectedToLogin() throws Exception {
        mockMvc.perform(get("/account/password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    void authenticatedUserCanOpenPasswordChangePage() throws Exception {
        mockMvc.perform(get("/account/password")
                        .with(user("password-page@example.com")))
                .andExpect(status().isOk())
                .andExpect(view().name("account/password"))
                .andExpect(content().string(containsString("修改密码")))
                .andExpect(content().string(containsString("name=\"currentPassword\"")))
                .andExpect(content().string(containsString("name=\"newPassword\"")));
    }

    @Test
    void queryParameterCannotForgePasswordChangeConfirmation() throws Exception {
        mockMvc.perform(get("/account/password").queryParam("changed", "false")
                        .with(user("forged-password-confirmation@example.com")))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        containsString("密码已修改"))));
    }

    @Test
    void validationErrorIsRenderedWithoutEchoingPasswords() throws Exception {
        String email = "password-page-error@example.com";
        registrationService.register(email, "current password");

        mockMvc.perform(post("/account/password")
                        .with(user(email))
                        .with(csrf())
                        .param("currentPassword", "wrong password")
                        .param("newPassword", "must never be echoed"))
                .andExpect(status().isOk())
                .andExpect(view().name("account/password"))
                .andExpect(model().attribute("errorMessage", "当前密码不正确"))
                .andExpect(content().string(containsString("当前密码不正确")))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        containsString("must never be echoed"))));
    }

    @Test
    void successfulSubmissionRedirectsToConfirmationPage() throws Exception {
        String email = "password-page-success@example.com";
        registrationService.register(email, "current password");

        MvcResult submission = mockMvc.perform(post("/account/password")
                        .with(user(email))
                        .with(csrf())
                        .param("currentPassword", "current password")
                        .param("newPassword", "new valid password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/password"))
                .andReturn();
        MockHttpSession session = (MockHttpSession) submission.getRequest().getSession(false);
        assertThat(session).isNotNull();

        mockMvc.perform(get("/account/password")
                        .session(session)
                        .with(user(email)))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("密码已修改")));

        mockMvc.perform(get("/account/password")
                        .session(session)
                        .with(user(email)))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        containsString("密码已修改"))));
    }

    @Test
    void repeatedWrongCurrentPasswordsRateLimitFurtherArgonChecks() throws Exception {
        String email = "password-page-rate-limit@example.com";
        registrationService.register(email, "current password");

        for (int attempt = 0; attempt < rateLimitProperties.maxFailuresPerEmail(); attempt++) {
            mockMvc.perform(post("/account/password")
                            .with(user(email))
                            .with(csrf())
                            .param("currentPassword", "wrong password")
                            .param("newPassword", "new valid password"))
                    .andExpect(status().isOk())
                    .andExpect(model().attribute("errorMessage", "当前密码不正确"));
        }

        mockMvc.perform(post("/account/password")
                        .with(user(email))
                        .with(csrf())
                        .param("currentPassword", "current password")
                        .param("newPassword", "new valid password"))
                .andExpect(status().isTooManyRequests())
                .andExpect((result) -> assertThat(result.getResponse().getErrorMessage())
                        .isEqualTo("密码验证尝试过于频繁，请稍后再试"));
    }
}
