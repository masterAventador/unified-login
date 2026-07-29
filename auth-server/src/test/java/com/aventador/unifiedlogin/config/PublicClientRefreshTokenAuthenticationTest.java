package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 守住自定义客户端认证路径的边界。
 *
 * <p>这条路径让公有客户端能凭 client_id 通过刷新请求的客户端认证。它一旦越界，
 * 后果是直接的安全事故——本类的每个用例对应一种越界方式，都必须一直是红线。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class PublicClientRefreshTokenAuthenticationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    private static final String PASSWORD = "a valid password";

    @Test
    void introspectEndpointRejectsRefreshGrantShapedRequest() throws Exception {
        // 客户端认证过滤器同时覆盖 token / introspect / revoke 等端点。自定义转换器若不限定
        // 端点，任何人带上公开的 client_id 再加一个与内省毫无关系的 grant_type=refresh_token，
        // 就能读出令牌里的 sub 与 email。
        String accessToken = issueAccessToken("boundary-introspect@example.com");

        mockMvc.perform(post("/oauth2/introspect")
                        .param("grant_type", "refresh_token")
                        .param("client_id", OAuth2TestFlows.CLIENT_ID)
                        .param("token", accessToken))
                .andExpect(status().is(not(200)))
                .andExpect(content().string(not(org.hamcrest.Matchers.containsString("\"active\""))));
    }

    @Test
    void revokeEndpointRejectsRefreshGrantShapedRequest() throws Exception {
        // 同上，越界到撤销端点意味着任何人可以撤销他人令牌，构成拒绝服务
        String email = "boundary-revoke@example.com";
        registrationService.register(email, PASSWORD);
        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                        OAuth2TestFlows.login(mockMvc, email, PASSWORD)));
        String refreshToken = OAuth2TestFlows.jsonField(tokenResponse, "refresh_token");

        mockMvc.perform(post("/oauth2/revoke")
                        .param("grant_type", "refresh_token")
                        .param("client_id", OAuth2TestFlows.CLIENT_ID)
                        .param("token", refreshToken))
                .andExpect(status().is(not(200)));

        // 只断言状态码不够：若这条路径将来退化成 500，"非 200" 依然成立，测试却漏掉了真正的
        // 危害。断言令牌仍然可用，才是这条用例真正要守的东西。
        String refreshed = OAuth2TestFlows.refreshTokens(mockMvc, refreshToken);
        assertThat(OAuth2TestFlows.jsonField(refreshed, "access_token")).isNotBlank();
    }

    @Test
    void authorizationCodeExchangeWithoutCodeVerifierIsRejected() throws Exception {
        // PKCE 是本系统唯一的客户端身份证明手段。自定义认证路径一旦扩到授权码流程，
        // 这条会变绿——它必须一直是红线。
        String code = authorizationCodeFor("boundary-noverifier@example.com");

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", OAuth2TestFlows.CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", OAuth2TestFlows.REDIRECT_URI))
                .andExpect(status().is(not(200)));
    }

    @Test
    void authorizationCodeExchangeWithWrongCodeVerifierIsRejected() throws Exception {
        String code = authorizationCodeFor("boundary-badverifier@example.com");

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", OAuth2TestFlows.CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", OAuth2TestFlows.REDIRECT_URI)
                        .param("code_verifier", "this-is-not-the-right-verifier-value-000000000"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    private String authorizationCodeFor(String email) throws Exception {
        registrationService.register(email, PASSWORD);
        return OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                OAuth2TestFlows.login(mockMvc, email, PASSWORD));
    }

    private String issueAccessToken(String email) throws Exception {
        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc, authorizationCodeFor(email));
        return OAuth2TestFlows.jsonField(tokenResponse, "access_token");
    }
}
