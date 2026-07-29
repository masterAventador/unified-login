package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import com.aventador.unifiedlogin.user.AppUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 账号状态必须管住 refresh token 授权，而不只是表单登录。
 *
 * <p>刷新授权用的是首次登录时序列化进 {@code oauth2_authorization.attributes} 的 principal 快照，
 * 天然不回查用户表；而每次刷新都会轮转出一把新的 30 天令牌。两者叠加的后果是：被禁用的账号
 * 只要保持活跃，就**永远不会失效**——后台点了「禁用」，用户照常访问所有产品。
 * 规格书 §10 把「账号已禁用 → 持有的 refresh token 也无法换取新 token」写为必须行为。
 *
 * <p>断言一律落在「有没有签发出可用凭证」这个终态上，不钉具体错误码：这条链路上有多个
 * provider 都可能拒绝，谁最后抛异常属于实现细节，钉死它换来的是偶发失败。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class AccountStatusRefreshTokenTest {

    private static final String PASSWORD = "a valid password";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void disabledAccountCannotExchangeRefreshTokenForNewTokens() throws Exception {
        String email = "refresh-disabled@example.com";
        String refreshToken = freshRefreshTokenFor(email).refreshToken();

        // 基线：禁用之前这把令牌确实换得动。少了这一步，后面的「被拒」可能只是因为令牌本来就是坏的
        String rotatedRefreshToken = OAuth2TestFlows.jsonField(
                OAuth2TestFlows.refreshTokens(mockMvc, refreshToken), "refresh_token");

        jdbcTemplate.update("UPDATE app_user SET status = 'DISABLED' WHERE email = ?", email);

        assertRefreshIssuesNothing(rotatedRefreshToken);
    }

    @Test
    void deletedAccountCannotExchangeRefreshTokenForNewTokens() throws Exception {
        String email = "refresh-deleted@example.com";
        String refreshToken = freshRefreshTokenFor(email).refreshToken();

        String rotatedRefreshToken = OAuth2TestFlows.jsonField(
                OAuth2TestFlows.refreshTokens(mockMvc, refreshToken), "refresh_token");

        jdbcTemplate.update("DELETE FROM app_user WHERE email = ?", email);

        assertRefreshIssuesNothing(rotatedRefreshToken);
    }

    /**
     * 反向锁定：把账号状态检查写成「一律拒绝」同样能让上面两条变绿，那样续期功能整体报废。
     * 因此这里断言的不是「返回了 200」，而是续期换来的令牌**确实还能访问受保护资源**。
     */
    @Test
    void activeAccountStillRefreshesIntoWorkingAccessToken() throws Exception {
        String email = "refresh-active@example.com";
        IssuedTokens issued = freshRefreshTokenFor(email);

        String accessToken = OAuth2TestFlows.jsonField(
                OAuth2TestFlows.refreshTokens(mockMvc, issued.refreshToken()), "access_token");

        mockMvc.perform(get("/userinfo").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value(issued.userId()));
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

    private record IssuedTokens(String userId, String refreshToken) {
    }

    private IssuedTokens freshRefreshTokenFor(String email) throws Exception {
        AppUser user = registrationService.register(email, PASSWORD);
        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                        OAuth2TestFlows.login(mockMvc, email, PASSWORD)));
        return new IssuedTokens(user.getId().toString(),
                OAuth2TestFlows.jsonField(tokenResponse, "refresh_token"));
    }
}
