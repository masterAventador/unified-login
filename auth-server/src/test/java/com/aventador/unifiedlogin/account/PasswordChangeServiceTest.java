package com.aventador.unifiedlogin.account;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.password.WeakPasswordException;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.security.LoginRateLimitProperties;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.AppUserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class PasswordChangeServiceTest {

    private static final String CURRENT_PASSWORD = "current password";

    private static final String NEW_PASSWORD = "new valid password";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private PasswordChangeService passwordChangeService;

    @Autowired
    private LoginRateLimitProperties rateLimitProperties;

    @Test
    void wrongCurrentPasswordHasNoSideEffectsAndLeavesRefreshTokenUsable() throws Exception {
        String email = "wrong-current-password@example.com";
        AppUser registered = registrationService.register(email, CURRENT_PASSWORD);
        String refreshToken = issueRefreshToken(email, CURRENT_PASSWORD);
        AppUser before = userRepository.findById(registered.getId()).orElseThrow();

        assertThatExceptionOfType(IncorrectCurrentPasswordException.class)
                .isThrownBy(() -> passwordChangeService.changePassword(
                        email, "definitely wrong", NEW_PASSWORD));

        AppUser after = userRepository.findById(registered.getId()).orElseThrow();
        assertThat(after.getPasswordHash()).isEqualTo(before.getPasswordHash());
        assertThat(after.getPasswordChangedAt()).isEqualTo(before.getPasswordChangedAt());

        String accessToken = OAuth2TestFlows.jsonField(
                OAuth2TestFlows.refreshTokens(mockMvc, refreshToken),
                "access_token");
        mockMvc.perform(get("/userinfo")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value(registered.getId().toString()));
    }

    @Test
    void weakNewPasswordHasNoSideEffectsAndLeavesRefreshTokenUsable() throws Exception {
        String email = "weak-new-password@example.com";
        AppUser registered = registrationService.register(email, CURRENT_PASSWORD);
        String refreshToken = issueRefreshToken(email, CURRENT_PASSWORD);
        AppUser before = userRepository.findById(registered.getId()).orElseThrow();

        assertThatExceptionOfType(WeakPasswordException.class)
                .isThrownBy(() -> passwordChangeService.changePassword(
                        email, CURRENT_PASSWORD, "short"));

        AppUser after = userRepository.findById(registered.getId()).orElseThrow();
        assertThat(after.getPasswordHash()).isEqualTo(before.getPasswordHash());
        assertThat(after.getPasswordChangedAt()).isEqualTo(before.getPasswordChangedAt());

        String accessToken = OAuth2TestFlows.jsonField(
                OAuth2TestFlows.refreshTokens(mockMvc, refreshToken),
                "access_token");
        mockMvc.perform(get("/userinfo")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value(registered.getId().toString()));
    }

    @Test
    void serviceRechecksAccountLimitAfterAcquiringUserLock() {
        String email = "password-service-rate-limit@example.com";
        registrationService.register(email, CURRENT_PASSWORD);

        for (int attempt = 0; attempt < rateLimitProperties.maxFailuresPerEmail(); attempt++) {
            assertThatExceptionOfType(IncorrectCurrentPasswordException.class)
                    .isThrownBy(() -> passwordChangeService.changePassword(
                            email, "wrong password", NEW_PASSWORD));
        }

        assertThatExceptionOfType(PasswordChangeRateLimitException.class)
                .isThrownBy(() -> passwordChangeService.changePassword(
                        email, CURRENT_PASSWORD, NEW_PASSWORD));
    }

    @Test
    void successfulChangeReplacesPasswordAndRevokesExistingRefreshTokens() throws Exception {
        String email = "successful-password-change@example.com";
        AppUser registered = registrationService.register(email, CURRENT_PASSWORD);
        IssuedSession issuedSession = issueRefreshTokenWithSession(email, CURRENT_PASSWORD);
        String refreshToken = issuedSession.refreshToken();
        AppUser before = userRepository.findById(registered.getId()).orElseThrow();

        passwordChangeService.changePassword(email, CURRENT_PASSWORD, NEW_PASSWORD);

        AppUser after = userRepository.findById(registered.getId()).orElseThrow();
        assertThat(after.getPasswordHash()).isNotEqualTo(before.getPasswordHash());
        assertThat(after.getPasswordChangedAt()).isAfter(before.getPasswordChangedAt());

        mockMvc.perform(formLogin("/login").user(email).password(CURRENT_PASSWORD))
                .andExpect(unauthenticated());
        OAuth2TestFlows.login(mockMvc, email, NEW_PASSWORD);

        // 已签发的自包含 access token 最长仍可使用 15 分钟；这里验证的是所有旧 refresh
        // token 立即失效，避免其他设备无限续期。
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", OAuth2TestFlows.CLIENT_ID)
                        .param("refresh_token", refreshToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andExpect(jsonPath("$.id_token").doesNotExist());

        MvcResult staleSessionAuthorization = mockMvc.perform(
                        get(OAuth2TestFlows.authorizeUri(OAuth2TestFlows.validAuthorizeParams()))
                                .session(issuedSession.session()))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        assertThat(staleSessionAuthorization.getResponse().getRedirectedUrl())
                .as("改密前的认证中心会话必须被迫重新登录，不能静默签发新授权码")
                .startsWith("/login");
    }

    private String issueRefreshToken(String email, String password) throws Exception {
        return issueRefreshTokenWithSession(email, password).refreshToken();
    }

    private IssuedSession issueRefreshTokenWithSession(String email, String password) throws Exception {
        MockHttpSession session = OAuth2TestFlows.login(mockMvc, email, password);
        String response = OAuth2TestFlows.exchangeCode(
                mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc, session));
        return new IssuedSession(session, OAuth2TestFlows.jsonField(response, "refresh_token"));
    }

    private record IssuedSession(MockHttpSession session, String refreshToken) {
    }
}
