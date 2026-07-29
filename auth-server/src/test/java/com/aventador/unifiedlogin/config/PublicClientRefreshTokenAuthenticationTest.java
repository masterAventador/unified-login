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

    // 「授权码换令牌时缺失 / 错误 code_verifier 被拒」这两条曾经也在本类，现已合并到
    // AuthorizationCodeFlowTest（那里的断言更强，且 PKCE 校验本身属于授权码协议一致性）。
    // 两处各守一半的结果是下次改动只有一处会被更新。

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
