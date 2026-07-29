package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import com.aventador.unifiedlogin.user.AppUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class JwtClaimsConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private JwtDecoder jwtDecoder;

    private static final String PASSWORD = "a valid password";

    @Test
    void accessTokenSubjectIsUserIdNotEmail() throws Exception {
        String email = "claims-sub@example.com";
        AppUser user = registrationService.register(email, PASSWORD);

        Jwt jwt = decodeAccessToken(email);

        assertThat(jwt.getSubject()).isEqualTo(user.getId().toString());
        assertThat(jwt.getSubject()).isNotEqualTo(email);
    }

    @Test
    void accessTokenCarriesEmailClaim() throws Exception {
        String email = "claims-email@example.com";
        registrationService.register(email, PASSWORD);

        Jwt jwt = decodeAccessToken(email);

        assertThat(jwt.getClaimAsString("email")).isEqualTo(email);
    }

    @Test
    void accessTokenCarriesNoRoleOrAuthorityClaim() throws Exception {
        String email = "claims-noroles@example.com";
        registrationService.register(email, PASSWORD);

        Jwt jwt = decodeAccessToken(email);

        // 规格书要求：认证中心不下发任何角色或权限信息
        assertThat(jwt.getClaims()).doesNotContainKeys("roles", "authorities", "scope_roles");
    }

    @Test
    void refreshedAccessTokenKeepsUserIdSubjectAndEmail() throws Exception {
        // 刷新令牌重新签发 access token 时同样走 customizer——这条分支若失守，
        // 用户在续期后会拿到 sub 为邮箱的令牌，产品侧的外键关联当场断裂
        String email = "claims-refresh@example.com";
        AppUser user = registrationService.register(email, PASSWORD);

        String code = OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                OAuth2TestFlows.login(mockMvc, email, PASSWORD));
        String initialTokenResponse = OAuth2TestFlows.exchangeCode(mockMvc, code);

        String initialAccessToken = OAuth2TestFlows.jsonField(initialTokenResponse, "access_token");
        String refreshToken = OAuth2TestFlows.jsonField(initialTokenResponse, "refresh_token");

        String refreshedTokenResponse = OAuth2TestFlows.refreshTokens(mockMvc, refreshToken);
        String refreshedAccessToken = OAuth2TestFlows.jsonField(refreshedTokenResponse, "access_token");

        // 必须确认换到的是新令牌，否则下面的断言可能只是把旧响应又验了一遍
        assertThat(refreshedAccessToken).isNotEqualTo(initialAccessToken);

        Jwt refreshedJwt = jwtDecoder.decode(refreshedAccessToken);
        assertThat(refreshedJwt.getSubject()).isEqualTo(user.getId().toString());
        assertThat(refreshedJwt.getClaimAsString("email")).isEqualTo(email);
    }

    @Test
    void refreshWithUnknownClientIsRejected() throws Exception {
        // 守住自定义客户端认证路径仍然校验客户端：若哪天校验被删，这条必须立刻变红
        String email = "claims-refresh-badclient@example.com";
        registrationService.register(email, PASSWORD);

        String code = OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                OAuth2TestFlows.login(mockMvc, email, PASSWORD));
        String refreshToken = OAuth2TestFlows.jsonField(
                OAuth2TestFlows.exchangeCode(mockMvc, code), "refresh_token");

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", "no-such-client")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void idTokenSubjectMatchesAccessTokenSubject() throws Exception {
        String email = "claims-idtoken@example.com";
        AppUser user = registrationService.register(email, PASSWORD);

        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                        OAuth2TestFlows.login(mockMvc, email, PASSWORD)));

        Jwt idToken = jwtDecoder.decode(OAuth2TestFlows.jsonField(tokenResponse, "id_token"));

        assertThat(idToken.getSubject()).isEqualTo(user.getId().toString());
    }

    private Jwt decodeAccessToken(String email) throws Exception {
        // 必须真实登录：.with(user(...)) 造的主体没有 FactorGrantedAuthority，
        // 框架推导不出认证时间会直接抛异常
        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                        OAuth2TestFlows.login(mockMvc, email, PASSWORD)));

        return jwtDecoder.decode(OAuth2TestFlows.jsonField(tokenResponse, "access_token"));
    }
}
