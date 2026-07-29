package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;

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
    private UserService userService;

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
        // 注意：刷新授权时 principal 是最初登录时序列化进 oauth2_authorization 表的快照，
        // 包含的是登录时的邮箱，框架用它来反序列化主体。customizer 查询用户时就是用这个
        // 邮箱，这与授权码交换的流程完全相同——只是来源不同（新登录 vs 缓存的授权记录）
        String email = "claims-refresh@example.com";
        AppUser user = registrationService.register(email, PASSWORD);

        String code = OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                OAuth2TestFlows.login(mockMvc, email, PASSWORD));
        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc, code);

        // 验证 access token 中的 sub 和 email 都正确
        Jwt accessToken = jwtDecoder.decode(OAuth2TestFlows.jsonField(tokenResponse, "access_token"));
        assertThat(accessToken.getSubject()).isEqualTo(user.getId().toString());
        assertThat(accessToken.getClaimAsString("email")).isEqualTo(email);

        // 验证 id token 也有正确的 sub
        Jwt idToken = jwtDecoder.decode(OAuth2TestFlows.jsonField(tokenResponse, "id_token"));
        assertThat(idToken.getSubject()).isEqualTo(user.getId().toString());
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
