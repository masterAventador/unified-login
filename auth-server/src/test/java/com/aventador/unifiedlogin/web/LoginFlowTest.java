package com.aventador.unifiedlogin.web;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class LoginFlowTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Test
    void loginPageIsPubliclyAccessible() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
    }

    @Test
    void correctCredentialsAuthenticate() throws Exception {
        registrationService.register("login-ok@example.com", "a valid password");

        mockMvc.perform(formLogin("/login").user("login-ok@example.com").password("a valid password"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void emailCaseIsIgnoredOnLogin() throws Exception {
        registrationService.register("login-case@example.com", "a valid password");

        mockMvc.perform(formLogin("/login").user("Login-Case@Example.COM").password("a valid password"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void wrongPasswordFailsWithGenericRedirect() throws Exception {
        registrationService.register("login-bad@example.com", "a valid password");

        mockMvc.perform(post("/login").with(csrf())
                        .param("username", "login-bad@example.com")
                        .param("password", "wrong password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void unknownEmailFailsIdenticallyToWrongPassword() throws Exception {
        mockMvc.perform(post("/login").with(csrf())
                        .param("username", "ghost@example.com")
                        .param("password", "a valid password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void protectedPageRedirectsToLoginWhenAnonymous() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }
}
