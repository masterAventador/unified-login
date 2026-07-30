package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import com.aventador.unifiedlogin.user.AppUser;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
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

    @Autowired
    private JWKSource<SecurityContext> jwkSource;

    @Autowired
    private JdbcTemplate jdbcTemplate;

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

    /**
     * 签发令牌时查不到用户，必须回标准 OAuth2 错误体而不是 500。
     *
     * <p>触发条件是账号在授权码 / refresh token 仍有效的窗口内被删除。接入方按规范解析令牌端点
     * 的 JSON 错误体，收到 500 时拿到的是一个解析不了的错误页，只能表现为「登录卡住」。
     * 断言落在响应形态上：状态码不是 5xx、body 是带 error 字段的 JSON、且没有任何令牌漏出去。
     */
    @Test
    void tokenExchangeForDeletedUserReturnsOAuth2ErrorInsteadOfServerError() throws Exception {
        String email = "claims-deleted@example.com";
        registrationService.register(email, PASSWORD);
        String code = OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                OAuth2TestFlows.login(mockMvc, email, PASSWORD));

        jdbcTemplate.update("DELETE FROM app_user WHERE email = ?", email);

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", OAuth2TestFlows.CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", OAuth2TestFlows.REDIRECT_URI)
                        .param("code_verifier", OAuth2TestFlows.CODE_VERIFIER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").isNotEmpty())
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andExpect(jsonPath("$.id_token").doesNotExist());
    }

    /**
     * 禁用账号后，旧的认证中心会话不能借 prompt=none 静默拿到新令牌。
     *
     * <p>Spring Authorization Server 会把首次登录的 principal 快照保存在 HTTP 会话里；
     * 仅让后续表单登录失败并不能使这个快照失效。这里先证明旧会话仍能走到授权码，再守住
     * 令牌签发边界，避免已禁用账号持续静默续期。
     */
    @Test
    void disabledAccountCannotExchangeCodeObtainedSilentlyFromExistingSession() throws Exception {
        String email = "claims-silent-disabled@example.com";
        registrationService.register(email, PASSWORD);
        MockHttpSession session = OAuth2TestFlows.login(mockMvc, email, PASSWORD);

        jdbcTemplate.update("UPDATE app_user SET status = 'DISABLED' WHERE email = ?", email);

        Map<String, String> authorizeParams = OAuth2TestFlows.validAuthorizeParams();
        authorizeParams.put("prompt", "none");
        authorizeParams.put("state", "silent-disabled-state");
        MvcResult authorization = mockMvc.perform(
                        get(OAuth2TestFlows.authorizeUri(authorizeParams)).session(session))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        Map<String, String> callbackParams = OAuth2TestFlows.queryParams(
                authorization.getResponse().getRedirectedUrl());
        assertThat(callbackParams)
                .containsEntry("state", "silent-disabled-state")
                .containsKey("code")
                .doesNotContainKey("error");

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", OAuth2TestFlows.CLIENT_ID)
                        .param("code", callbackParams.get("code"))
                        .param("redirect_uri", OAuth2TestFlows.REDIRECT_URI)
                        .param("code_verifier", OAuth2TestFlows.CODE_VERIFIER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").isNotEmpty())
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andExpect(jsonPath("$.id_token").doesNotExist());
    }

    @Test
    void idTokenSubjectMatchesAccessTokenSubject() throws Exception {
        String email = "claims-idtoken@example.com";
        AppUser user = registrationService.register(email, PASSWORD);

        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                        OAuth2TestFlows.login(mockMvc, email, PASSWORD)));

        Jwt idToken = decodeIdToken(OAuth2TestFlows.jsonField(tokenResponse, "id_token"));

        assertThat(idToken.getSubject()).isEqualTo(user.getId().toString());
    }

    @Test
    void resourceServerDecoderRejectsIdToken() throws Exception {
        String email = "claims-idtoken-bearer@example.com";
        registrationService.register(email, PASSWORD);

        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                        OAuth2TestFlows.login(mockMvc, email, PASSWORD)));
        String idToken = OAuth2TestFlows.jsonField(tokenResponse, "id_token");

        assertThatThrownBy(() -> jwtDecoder.decode(idToken))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void accessAndIdTokensUseDistinctStandardTokenTypes() throws Exception {
        String email = "claims-token-types@example.com";
        registrationService.register(email, PASSWORD);

        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                        OAuth2TestFlows.login(mockMvc, email, PASSWORD)));
        Jwt accessToken = jwtDecoder.decode(OAuth2TestFlows.jsonField(tokenResponse, "access_token"));
        Jwt idToken = decodeIdToken(OAuth2TestFlows.jsonField(tokenResponse, "id_token"));

        assertThat(accessToken.getHeaders()).containsEntry("typ", "at+jwt");
        assertThat(idToken.getHeaders()).containsEntry("typ", "JWT");
    }

    private Jwt decodeAccessToken(String email) throws Exception {
        // 必须真实登录：.with(user(...)) 造的主体没有 FactorGrantedAuthority，
        // 框架推导不出认证时间会直接抛异常
        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                        OAuth2TestFlows.login(mockMvc, email, PASSWORD)));

        return jwtDecoder.decode(OAuth2TestFlows.jsonField(tokenResponse, "access_token"));
    }

    private Jwt decodeIdToken(String token) {
        return NimbusJwtDecoder.withJwkSource(jwkSource)
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build()
                .decode(token);
    }
}
