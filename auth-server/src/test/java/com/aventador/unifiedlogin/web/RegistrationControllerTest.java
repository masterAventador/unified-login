package com.aventador.unifiedlogin.web;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class RegistrationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Test
    void registrationPageIsPubliclyAccessible() throws Exception {
        mockMvc.perform(get("/register"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"));
    }

    @Test
    void successfulSubmissionCreatesUserAndRedirectsToLogin() throws Exception {
        mockMvc.perform(post("/register").with(csrf())
                        .param("email", "web-signup@example.com")
                        .param("password", "a valid password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?registered"));

        assertThat(registrationService.isEmailTaken("web-signup@example.com")).isTrue();
    }

    @Test
    void duplicateEmailRendersFormWithError() throws Exception {
        registrationService.register("taken@example.com", "a valid password");

        mockMvc.perform(post("/register").with(csrf())
                        .param("email", "taken@example.com")
                        .param("password", "a valid password"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"))
                .andExpect(model().attributeExists("errorMessage"));
    }

    @Test
    void invalidEmailRendersFormWithError() throws Exception {
        mockMvc.perform(post("/register").with(csrf())
                        .param("email", "not-an-email")
                        .param("password", "a valid password"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"))
                .andExpect(model().attributeExists("errorMessage"));
    }

    @Test
    void weakPasswordRendersFormWithError() throws Exception {
        mockMvc.perform(post("/register").with(csrf())
                        .param("email", "weak-web@example.com")
                        .param("password", "short"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"))
                .andExpect(model().attributeExists("errorMessage"));
    }

    @Test
    void submissionWithoutCsrfTokenIsRejected() throws Exception {
        mockMvc.perform(post("/register")
                        .param("email", "no-csrf@example.com")
                        .param("password", "a valid password"))
                .andExpect(status().isForbidden());
    }
}
