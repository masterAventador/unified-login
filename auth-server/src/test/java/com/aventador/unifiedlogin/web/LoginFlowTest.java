package com.aventador.unifiedlogin.web;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class LoginFlowTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

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
                .andExpect(authenticated());
    }

    @Test
    void emailCaseIsIgnoredOnLogin() throws Exception {
        registrationService.register("login-case@example.com", "a valid password");

        mockMvc.perform(formLogin("/login").user("Login-Case@Example.COM").password("a valid password"))
                .andExpect(authenticated());
    }

    @Test
    void wrongPasswordFailsWithGenericRedirect() throws Exception {
        registrationService.register("login-bad@example.com", "a valid password");

        mockMvc.perform(post("/login").with(csrf())
                        .param("username", "login-bad@example.com")
                        .param("password", "wrong password"))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void unknownEmailFailsIdenticallyToWrongPassword() throws Exception {
        mockMvc.perform(post("/login").with(csrf())
                        .param("username", "ghost@example.com")
                        .param("password", "a valid password"))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void disabledAccountFailsIdenticallyToWrongPassword() throws Exception {
        String email = "login-disabled@example.com";
        registrationService.register(email, "a valid password");
        jdbcTemplate.update("UPDATE app_user SET status = 'DISABLED' WHERE email = ?", email);

        // 密码正确但账号被禁用：对外表现必须与密码错误完全一致，否则泄漏「账号存在但被禁用」
        mockMvc.perform(formLogin("/login").user(email).password("a valid password"))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void protectedPageRedirectsToLoginWhenAnonymous() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }
}
