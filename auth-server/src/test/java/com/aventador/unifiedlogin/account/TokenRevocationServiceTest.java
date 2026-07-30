package com.aventador.unifiedlogin.account;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import com.aventador.unifiedlogin.user.AppUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 撤销能力的断言落在 OAuth 端点的真实终态，而不是数据库行数或 mock 调用次数上。
 *
 * <p>同一个用例同时守住两种危险回归：撤销变成空实现时，目标用户的旧 refresh token
 * 会重新换出令牌；撤销范围放大到全表时，另一用户的 refresh token 会一并失效。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class TokenRevocationServiceTest {

    private static final String PASSWORD = "a valid password";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private TokenRevocationService tokenRevocationService;

    @Test
    void revokeAllTokensOfInvalidatesOnlyTheSelectedUsersRefreshTokens() throws Exception {
        IssuedTokens target = issueTokens("revoke-target@example.com");
        IssuedTokens other = issueTokens("revoke-other@example.com");

        // 先各轮转一次，证明传给撤销逻辑的两把 refresh token 原本都真实可用。
        String targetRefreshToken = rotatedRefreshToken(target.refreshToken());
        String otherRefreshToken = rotatedRefreshToken(other.refreshToken());

        tokenRevocationService.revokeAllTokensOf(target.userId());

        assertRefreshIssuesNothing(targetRefreshToken);

        String otherAccessToken = OAuth2TestFlows.jsonField(
                OAuth2TestFlows.refreshTokens(mockMvc, otherRefreshToken),
                "access_token");
        mockMvc.perform(get("/userinfo")
                        .header("Authorization", "Bearer " + otherAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value(other.userId().toString()));
    }

    private IssuedTokens issueTokens(String email) throws Exception {
        AppUser user = registrationService.register(email, PASSWORD);
        MockHttpSession session = OAuth2TestFlows.login(mockMvc, email, PASSWORD);
        String response = OAuth2TestFlows.exchangeCode(
                mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc, session));
        return new IssuedTokens(
                user.getId(),
                OAuth2TestFlows.jsonField(response, "refresh_token"));
    }

    private String rotatedRefreshToken(String refreshToken) throws Exception {
        return OAuth2TestFlows.jsonField(
                OAuth2TestFlows.refreshTokens(mockMvc, refreshToken),
                "refresh_token");
    }

    private void assertRefreshIssuesNothing(String refreshToken) throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", OAuth2TestFlows.CLIENT_ID)
                        .param("refresh_token", refreshToken))
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andExpect(jsonPath("$.id_token").doesNotExist());
    }

    private record IssuedTokens(java.util.UUID userId, String refreshToken) {
    }
}
