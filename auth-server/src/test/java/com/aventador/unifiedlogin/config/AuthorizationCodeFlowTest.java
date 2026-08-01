package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import com.aventador.unifiedlogin.user.EmailAddress;
import com.aventador.unifiedlogin.user.UserService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static com.aventador.unifiedlogin.support.OAuth2TestFlows.CLIENT_ID;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.CODE_VERIFIER;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.REDIRECT_URI;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.authorizeAndExtractCode;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.authorizeUri;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.exchangeCode;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.jsonField;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.refreshTokens;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.validAuthorizeParams;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 授权码 + PKCE 全流程的协议一致性验收。
 *
 * <p>本类不针对某一个类，而是把「用户登录 → 授权 → 换令牌 → 用令牌 → 续期」这条真实链路
 * 以及它周边的拒绝路径整体钉住。任何一条变红都意味着协议层面出了问题。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class AuthorizationCodeFlowTest {

    private static final String USER_EMAIL = "flow@example.com";

    private static final String PASSWORD = "a valid password";

    /** 公有客户端，会在用例中途被摘掉刷新能力，用来验证「授权类型含 refresh_token」那道校验。 */
    private static final String CLIENT_WITHOUT_REFRESH_GRANT = "test-no-refresh-grant";

    /** 机密客户端，用来验证「认证方式含 NONE」那道校验。 */
    private static final String CONFIDENTIAL_CLIENT = "test-confidential";

    private static final String OTHER_PUBLIC_CLIENT = "test-other-public";

    private static final String DESKTOP_CLIENT = "demo-desktop";

    /** 与 demo-web-a 一致的公有客户端设置，保证测试客户端走的是同一条产品路径。 */
    private static final ClientSettings PUBLIC_CLIENT_SETTINGS = ClientSettings.builder()
            .requireProofKey(true)
            .requireAuthorizationConsent(false)
            .build();

    private static final TokenSettings ROTATING_TOKEN_SETTINGS = TokenSettings.builder()
            .reuseRefreshTokens(false)
            .build();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private UserService userService;

    private MockHttpSession session;

    @BeforeEach
    void createUserAndLogin() throws Exception {
        if (!registrationService.isEmailTaken(USER_EMAIL)) {
            registrationService.register(USER_EMAIL, PASSWORD);
        }
        // 走真实登录：.with(user(...)) 的主体缺少 FactorGrantedAuthority，
        // 框架签发 token 时推导不出认证时间会直接抛异常
        session = OAuth2TestFlows.login(mockMvc, USER_EMAIL, PASSWORD);
    }

    @Test
    void authenticatedUserExchangesCodeForTokens() throws Exception {
        String code = authorizeAndExtractCode(mockMvc, session);

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.refresh_token").exists())
                .andExpect(jsonPath("$.id_token").exists())
                .andExpect(jsonPath("$.token_type").value("Bearer"));
    }

    @Test
    void desktopLoopbackRedirectAcceptsEphemeralPortButKeepsRegisteredHostAndPath() throws Exception {
        String runtimeRedirectUri = "http://127.0.0.1:49152/callback";
        String code = authorizeAndExtractCode(mockMvc, session, DESKTOP_CLIENT, runtimeRedirectUri);

        String tokenResponse = exchangeCode(
                mockMvc,
                code,
                DESKTOP_CLIENT,
                runtimeRedirectUri);

        assertThat(jsonField(tokenResponse, "access_token")).isNotBlank();
        assertThat(jsonField(tokenResponse, "refresh_token")).isNotBlank();

        Map<String, String> wrongPath = validAuthorizeParams(
                DESKTOP_CLIENT,
                "http://127.0.0.1:49152/attacker");
        mockMvc.perform(get(authorizeUri(wrongPath)).session(session))
                .andExpect(status().isBadRequest());
    }

    /**
     * PKCE 校验不通过必须拒发令牌。
     *
     * <p>本类是这条用例的唯一归属：PKCE 是授权码协议一致性的核心，与本类其余用例同源。
     * 它同时守着「自定义客户端认证路径不得扩到授权码流程」这条红线——那条路径一旦越界，
     * code_verifier 就不再被校验，本条会立刻变绿。原先 PublicClientRefreshTokenAuthenticationTest
     * 里的同名用例已删除，避免两处各守一半、改动时只更新其中一处。
     */
    @Test
    void tokenRequestWithWrongVerifierIsRejected() throws Exception {
        String code = authorizeAndExtractCode(mockMvc, session);

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", "wrong-verifier-value-that-does-not-match-challenge"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                // 只看状态码不够：必须确认没有任何令牌随着这次失败漏出去
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.id_token").doesNotExist());
    }

    @Test
    void authorizationCodeCannotBeUsedTwice() throws Exception {
        String code = authorizeAndExtractCode(mockMvc, session);

        String refreshTokenFromFirstUse = jsonField(exchangeCode(mockMvc, code), "refresh_token");

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));

        // 授权码被重放说明它很可能已经泄漏，OAuth 2.1 要求把它换出的令牌一并作废。
        // 只断言第二次换取失败守不住这一点：攻击者拿不到新令牌，却仍可能继续用旧的续期。
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", CLIENT_ID)
                        .param("refresh_token", refreshTokenFromFirstUse))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void authorizationRequestWithoutPkceIsRejected() throws Exception {
        Map<String, String> params = validAuthorizeParams();
        params.remove("code_challenge");
        params.remove("code_challenge_method");

        MvcResult result = mockMvc.perform(get(authorizeUri(params)).session(session))
                .andExpect(status().isFound())
                .andReturn();

        // 实测行为：requireProofKey(true) 生效时，框架不是返回 400，而是按 RFC 6749
        // §4.1.2.1 把 error 经**已注册的**回调地址回传。这仍然是拒绝，判据是回调里没有授权码
        // ——若 requireProofKey 被关掉，同一个请求会带着 code 跳回来，本用例照样变红。
        String location = result.getResponse().getRedirectedUrl();
        assertThat(location).startsWith(REDIRECT_URI);

        Map<String, String> callback = OAuth2TestFlows.queryParams(location);
        assertThat(callback).containsEntry("error", "invalid_request");
        assertThat(callback).doesNotContainKey("code");
    }

    @Test
    void redirectUriOutsideWhitelistIsRejectedWithoutRedirecting() throws Exception {
        Map<String, String> params = validAuthorizeParams();
        params.put("redirect_uri", "https://attacker.example.com/steal");

        MvcResult result = mockMvc.perform(get(authorizeUri(params)).session(session))
                .andExpect(status().isBadRequest())
                .andReturn();

        // 关键断言：绝不能发生指向攻击者地址的重定向
        assertThat(result.getResponse().getRedirectedUrl()).isNull();
    }

    @Test
    void userinfoReturnsSubjectWithValidAccessToken() throws Exception {
        // Task 8 只验证了「无 token 得 401」；这里补上正向链路：带合法 token 得 200
        String tokenResponse = exchangeCode(mockMvc, authorizeAndExtractCode(mockMvc, session));
        String accessToken = jsonField(tokenResponse, "access_token");

        UUID expectedUserId = userService.findByEmail(new EmailAddress(USER_EMAIL))
                .orElseThrow(() -> new AssertionError("测试用户应已存在：" + USER_EMAIL))
                .getId();

        mockMvc.perform(get("/userinfo").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                // sub 必须是用户 UUID：断言 exists() 会放过「回了邮箱」这种最容易发生的退化
                .andExpect(jsonPath("$.sub").value(expectedUserId.toString()));
    }

    @Test
    void refreshTokenRotatesAndReplayRevokesTheRotatedChain() throws Exception {
        String tokenResponse = exchangeCode(mockMvc, authorizeAndExtractCode(mockMvc, session));
        String firstRefreshToken = jsonField(tokenResponse, "refresh_token");

        String rotatedResponse = refreshTokens(mockMvc, firstRefreshToken);
        String secondRefreshToken = jsonField(rotatedResponse, "refresh_token");

        // 先确认真的换了一把新的：reuseRefreshTokens(false) 若失效，返回的会是同一个值，
        // 下一步的「旧令牌被拒」也就无从谈起了
        assertThat(secondRefreshToken).isNotEqualTo(firstRefreshToken);

        // 重放发生前，新令牌必须能继续续期；否则只是把刷新功能整体写坏了。
        String thirdRefreshToken = jsonField(refreshTokens(mockMvc, secondRefreshToken), "refresh_token");

        // 轮转后旧 refresh token 必须失效，且第二次提交代表凭证泄漏。
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", CLIENT_ID)
                        .param("refresh_token", firstRefreshToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));

        // 泄漏后必须撤销整个轮转链，而不是退回框架默认的“只拒绝被复用的那一把”。
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", CLIENT_ID)
                        .param("refresh_token", thirdRefreshToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    /**
     * 记录现状：完全不带 code_verifier 的换取请求被拒，但响应形态不符合 OAuth 规范
     * ——返回 302 跳登录页，而不是 400 + invalid_grant。
     *
     * <p>成因是这类请求匹配不上任何客户端认证转换器，于是没通过端点自身的鉴权就被
     * 异常处理转到了登录入口，压根没走到令牌逻辑。安全上无害（没有任何令牌签发），
     * 但接入方按规范解析 JSON 错误体会拿到一个重定向。是否改成 400 需要单独决策，
     * 这里先把当前形态钉住，改动时这条会变红，逼出一次有意识的选择。
     *
     * <p>与上一条同理，本类是这条用例的唯一归属；
     * PublicClientRefreshTokenAuthenticationTest 里那条只断言 is(not(200)) 的同类用例已删除。
     */
    @Test
    void tokenRequestWithoutCodeVerifierRedirectsInsteadOfReturningInvalidGrant() throws Exception {
        String code = authorizeAndExtractCode(mockMvc, session);

        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isFound())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl()).endsWith("/login");

        // 形态不规范不要紧，没签发令牌才是底线。重定向响应的 body 恒为空串，对它断言
        // "不含 access_token" 任何情况下都不会失败，是装饰性断言——改成证明这次请求
        // 对授权码毫无影响：它既没被消费、也没换出过任何东西，带上正确的 verifier 仍能正常兑换。
        assertThat(jsonField(exchangeCode(mockMvc, code), "access_token")).isNotBlank();
    }

    /**
     * 客户端被摘掉刷新能力后，它手上已经签发出去的 refresh token 必须立刻失效。
     *
     * <p>令牌必须是**这个客户端自己的**：拿别的客户端的 refresh token 来试，会先撞上归属校验，
     * 「该客户端不许刷新」这条根本轮不到执行，用例也就丧失了区分力（已实测确认）。
     *
     * <p><b>断言落在「没签发任何令牌」而不是具体错误码</b>：这条链路上有多个 provider 都会
     * 拒绝，谁最后抛异常取决于 ProviderManager 的遍历结果，钉死某个错误码会得到一条偶发失败、
     * 且失败输出与「安全校验被删除」逐字相同的用例——在专门守红线的套件里，这种狼来了代价太高。
     * 自定义 provider 那两道校验改由 {@link PublicClientRefreshTokenAuthenticationProviderTest}
     * 直接调 authenticate() 确定性地钉住。
     */
    @Test
    void refreshIsRejectedAfterClientLosesRefreshTokenGrant() throws Exception {
        saveClient(CLIENT_WITHOUT_REFRESH_GRANT, (builder) -> builder
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientSettings(PUBLIC_CLIENT_SETTINGS)
                .tokenSettings(ROTATING_TOKEN_SETTINGS));

        String refreshToken = jsonField(exchangeCode(mockMvc,
                authorizeAndExtractCode(mockMvc, session, CLIENT_WITHOUT_REFRESH_GRANT),
                CLIENT_WITHOUT_REFRESH_GRANT), "refresh_token");

        // 基线：摘能力之前它确实刷得动。少了这一步，后面的「被拒」可能只是因为令牌一开始就是坏的
        String rotatedRefreshToken = jsonField(
                refreshTokens(mockMvc, refreshToken, CLIENT_WITHOUT_REFRESH_GRANT), "refresh_token");

        // 撤掉刷新能力，其余登记信息不变
        saveClient(CLIENT_WITHOUT_REFRESH_GRANT, (builder) -> builder
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientSettings(PUBLIC_CLIENT_SETTINGS)
                .tokenSettings(ROTATING_TOKEN_SETTINGS));

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", CLIENT_WITHOUT_REFRESH_GRANT)
                        .param("refresh_token", rotatedRefreshToken))
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.refresh_token").doesNotExist());
    }

    /**
     * 只报一个公开的 client_id 不能冒充机密客户端。
     *
     * <p>同上，断言落在「没签发任何令牌」上而不是具体错误码——拒绝由哪个 provider 作出
     * 属于实现细节，钉死它只会换来偶发失败。
     */
    @Test
    void refreshIsRejectedForConfidentialClientPresentingOnlyClientId() throws Exception {
        // 机密客户端：认证方式里没有 NONE，凭 client_id 不足以证明身份
        saveClient(CONFIDENTIAL_CLIENT, (builder) -> builder
                .clientSecret("{noop}confidential-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN));

        String refreshToken = jsonField(
                exchangeCode(mockMvc, authorizeAndExtractCode(mockMvc, session)), "refresh_token");

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", CONFIDENTIAL_CLIENT)
                        .param("refresh_token", refreshToken))
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.refresh_token").doesNotExist());

        // 拒绝不该殃及池鱼：被当作道具的那个真实令牌必须还能正常续期
        assertThat(jsonField(refreshTokens(mockMvc, refreshToken), "access_token")).isNotBlank();
    }

    /**
     * 甲客户端拿到的 refresh token，乙客户端拿去换不出任何东西。
     *
     * <p>守的是令牌归属：refresh token 与签发它的客户端绑定，换个 client_id 报上来必须被拒。
     * 这条此前只在一次人工排查中验证过，没有留下回归网——而「验证过但没人守着」正是本项目
     * 反复栽跟头的形态，所以固化成常驻用例。
     */
    @Test
    void refreshTokenIssuedToOneClientCannotBeUsedByAnother() throws Exception {
        saveClient(OTHER_PUBLIC_CLIENT, (builder) -> builder
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientSettings(PUBLIC_CLIENT_SETTINGS)
                .tokenSettings(ROTATING_TOKEN_SETTINGS));

        // 令牌属于默认客户端
        String victimRefreshToken = jsonField(
                exchangeCode(mockMvc, authorizeAndExtractCode(mockMvc, session)), "refresh_token");

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", OTHER_PUBLIC_CLIENT)
                        .param("refresh_token", victimRefreshToken))
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.refresh_token").doesNotExist());

        // 被盗用未遂不该连累受害者：原客户端仍能正常续期
        assertThat(jsonField(refreshTokens(mockMvc, victimRefreshToken), "access_token")).isNotBlank();
    }

    /**
     * 清掉本类注册的测试专用客户端。
     *
     * <p>所有测试类共用同一个库，这两个客户端会残留到整个套件结束：一个停在被摘掉刷新授权的
     * 状态，另一个是带密钥的机密客户端。将来任何一条「枚举全部注册客户端」或「系统内不应存在
     * 机密客户端」的回归用例都会因此莫名其妙地红——后者对这个全公有客户端的项目很自然。
     */
    @AfterAll
    static void removeTestOnlyClients(@Autowired JdbcTemplate jdbcTemplate) {
        jdbcTemplate.update("DELETE FROM oauth2_authorization WHERE registered_client_id IN "
                        + "(SELECT id FROM oauth2_registered_client WHERE client_id IN (?, ?, ?))",
                CLIENT_WITHOUT_REFRESH_GRANT, CONFIDENTIAL_CLIENT, OTHER_PUBLIC_CLIENT);
        jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE client_id IN (?, ?, ?)",
                CLIENT_WITHOUT_REFRESH_GRANT, CONFIDENTIAL_CLIENT, OTHER_PUBLIC_CLIENT);

        // 清理必须自证：静默失效的清理和没写清理是一回事
        assertThat(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM oauth2_registered_client WHERE client_id IN (?, ?, ?)",
                Integer.class, CLIENT_WITHOUT_REFRESH_GRANT, CONFIDENTIAL_CLIENT, OTHER_PUBLIC_CLIENT)).isZero();
    }

    /**
     * 幂等注册一个测试专用客户端。
     *
     * <p>Spring 上下文在同一批测试里复用，同一个 clientId 重复 insert 会撞唯一约束，
     * 因此沿用已存在的主键——与 {@code ClientSyncRunner} 的同步策略一致。
     */
    private void saveClient(String clientId, Consumer<RegisteredClient.Builder> customizer) {
        RegisteredClient existing = registeredClientRepository.findByClientId(clientId);
        String id = (existing != null) ? existing.getId() : UUID.randomUUID().toString();

        RegisteredClient.Builder builder = RegisteredClient.withId(id)
                .clientId(clientId)
                .redirectUri(REDIRECT_URI)
                .scope(OidcScopes.OPENID);
        customizer.accept(builder);

        registeredClientRepository.save(builder.build());
    }
}
