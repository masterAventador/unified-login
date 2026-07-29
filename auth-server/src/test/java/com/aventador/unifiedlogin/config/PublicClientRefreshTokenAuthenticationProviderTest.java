package com.aventador.unifiedlogin.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * 直接对自定义客户端认证 provider 做单元测试。
 *
 * <p><b>为什么必须在这一层测</b>：走 HTTP 测不出这些分支。ProviderManager 捕获到某个
 * provider 抛出的 AuthenticationException 后只是记进 lastException 便**继续遍历下一个**
 * provider，最终对外呈现的错误来自框架自带的 {@code PublicClientAuthenticationProvider}。
 * 实测把本类的整个拒绝分支改成 {@code return null}（弃权），端到端 93 个用例全绿——
 * 因为框架那条路径会独立地再拒一次。HTTP 契约等价不代表分支被守住，只有直接调
 * {@code authenticate()} 才能确定性地钉住这里的行为。
 */
class PublicClientRefreshTokenAuthenticationProviderTest {

    private static final String CLIENT_ID = "unit-test-client";

    @Test
    void rejectsUnregisteredClient() {
        PublicClientRefreshTokenAuthenticationProvider provider = providerWith(client((builder) -> builder
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)));

        assertInvalidClient(provider, refreshTokenAuthentication("no-such-client"));
    }

    @Test
    void rejectsClientWhoseAuthenticationMethodsExcludeNone() {
        // 机密客户端：认证方式里没有 NONE。放行等于只凭一个公开的 client_id 就能冒充它，
        // 它的密钥形同虚设
        PublicClientRefreshTokenAuthenticationProvider provider = providerWith(client((builder) -> builder
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)));

        assertInvalidClient(provider, refreshTokenAuthentication(CLIENT_ID));
    }

    @Test
    void rejectsClientWhoseGrantTypesExcludeRefreshToken() {
        PublicClientRefreshTokenAuthenticationProvider provider = providerWith(client((builder) -> builder
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)));

        assertInvalidClient(provider, refreshTokenAuthentication(CLIENT_ID));
    }

    @Test
    void authenticatesPublicClientAllowedToRefresh() {
        RegisteredClient registeredClient = client((builder) -> builder
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN));
        PublicClientRefreshTokenAuthenticationProvider provider = providerWith(registeredClient);

        OAuth2ClientAuthenticationToken result = (OAuth2ClientAuthenticationToken) provider
                .authenticate(refreshTokenAuthentication(CLIENT_ID));

        // 没有这条正向用例，「永远抛 invalid_client」也能让上面三条全绿
        assertThat(result).isNotNull();
        assertThat(result.getRegisteredClient()).isEqualTo(registeredClient);
        assertThat(result.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
    }

    @Test
    void abstainsFromRequestsCarryingClientCredentials() {
        // 返回 null 表示弃权，交回框架自己的 provider。抢过来处理等于用一条只认 client_id
        // 的路径替换掉真正的凭证校验
        PublicClientRefreshTokenAuthenticationProvider provider = providerWith(client((builder) -> builder
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)));

        OAuth2ClientAuthenticationToken clientSecretAuthentication = new OAuth2ClientAuthenticationToken(
                CLIENT_ID, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "secret",
                Map.<String, Object>of(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue()));

        assertThat(provider.authenticate(clientSecretAuthentication)).isNull();
    }

    @Test
    void abstainsFromAuthorizationCodeExchange() {
        // 授权码流程必须继续由框架校验 code_verifier——PKCE 是本系统唯一的客户端身份证明手段
        PublicClientRefreshTokenAuthenticationProvider provider = providerWith(client((builder) -> builder
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)));

        OAuth2ClientAuthenticationToken authorizationCodeAuthentication = new OAuth2ClientAuthenticationToken(
                CLIENT_ID, ClientAuthenticationMethod.NONE, null,
                Map.<String, Object>of(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));

        assertThat(provider.authenticate(authorizationCodeAuthentication)).isNull();
    }

    private static void assertInvalidClient(PublicClientRefreshTokenAuthenticationProvider provider,
                                            OAuth2ClientAuthenticationToken authentication) {
        assertThatExceptionOfType(OAuth2AuthenticationException.class)
                .isThrownBy(() -> provider.authenticate(authentication))
                .satisfies((ex) -> assertThat(ex.getError().getErrorCode())
                        .isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT));
    }

    /** 刷新请求经转换器造出的客户端认证令牌形态。 */
    private static OAuth2ClientAuthenticationToken refreshTokenAuthentication(String clientId) {
        return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null,
                Map.<String, Object>of(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue()));
    }

    private static RegisteredClient client(Consumer<RegisteredClient.Builder> customizer) {
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .redirectUri("http://localhost:5173/callback")
                .scope(OidcScopes.OPENID);
        customizer.accept(builder);
        return builder.build();
    }

    /** 用真实的内存实现而非 mock：这里要验的是 provider 的判断，不是它怎么调仓储。 */
    private static PublicClientRefreshTokenAuthenticationProvider providerWith(RegisteredClient... clients) {
        RegisteredClientRepository repository = new InMemoryRegisteredClientRepository(clients);
        return new PublicClientRefreshTokenAuthenticationProvider(repository);
    }
}
