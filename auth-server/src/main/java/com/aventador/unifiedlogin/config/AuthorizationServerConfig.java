package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.security.LoginPaths;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.header.writers.DelegatingRequestMatcherHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
            RegisteredClientRepository registeredClientRepository,
            AuthorizationServerSettings authorizationServerSettings,
            OAuth2AuthorizationService authorizationService,
            UserDetailsService userDetailsService) throws Exception {
        // Spring Security 7 中该类没有 authorizationServer() 静态工厂（那是旧 1.x 的 API），
        // 用无参构造——照旧文档写静态工厂会编译失败
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();
        RequestMatcher nonAuthorizationEndpoint = new NegatedRequestMatcher(
                PathPatternRequestMatcher.pathPattern(authorizationServerSettings.getAuthorizationEndpoint()));

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                // 公有客户端的刷新请求过不了框架内置的客户端认证（内置转换器都要求
                // code_verifier 或密钥），必须补一条自己的认证路径，见规格书 §6.3
                .with(authorizationServerConfigurer, (authorizationServer) -> authorizationServer
                        .clientAuthentication((clientAuthentication) -> clientAuthentication
                                .authenticationConverter(new PublicClientRefreshTokenAuthenticationConverter(
                                        authorizationServerSettings))
                                .authenticationProvider(new PublicClientRefreshTokenAuthenticationProvider(
                                        registeredClientRepository)))
                        // 账号被禁用或删除后，它手上的 refresh token 必须立刻失效（规格书 §10）。
                        // 这里是**替换**掉框架的刷新 provider 而不是在它前面追加一个，原因见
                        // AccountStatusRefreshTokenAuthenticationProvider 的类注释
                        .tokenEndpoint((tokenEndpoint) -> tokenEndpoint
                                .authenticationProviders((authenticationProviders) ->
                                        AccountStatusRefreshTokenAuthenticationProvider.guardRefreshTokenProvider(
                                                authenticationProviders, authorizationService, userDetailsService)))
                        .authorizationServerMetadataEndpoint((metadataEndpoint) -> metadataEndpoint
                                .authorizationServerMetadataCustomizer(
                                        AuthorizationServerConfig::customizeAdvertisedCapabilities))
                        .oidc((oidc) -> oidc
                                .providerConfigurationEndpoint((providerConfiguration) ->
                                        providerConfiguration.providerConfigurationCustomizer(
                                                AuthorizationServerConfig::customizeAdvertisedCapabilities))))
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated())
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new PromptNoneAuthenticationEntryPoint(
                                        registeredClientRepository,
                                        new LoginUrlAuthenticationEntryPoint(LoginPaths.LOGIN)),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                // 静默续签通过隐藏 iframe 请求授权端点，该响应不能带 DENY。
                // 其他认证中心端点仍由定向 header writer 保持点击劫持保护。
                .headers((headers) -> headers
                        .frameOptions((frameOptions) -> frameOptions.disable())
                        .addHeaderWriter(new DelegatingRequestMatcherHeaderWriter(
                                nonAuthorizationEndpoint,
                                new XFrameOptionsHeaderWriter())))
                // 必需：/userinfo 端点自身不解析 Bearer token，靠资源服务器过滤器
                // 先完成认证。缺这一句该端点对任何合法 token 都返回拒绝
                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));

        return http.build();
    }

    private static void customizeAdvertisedCapabilities(OAuth2AuthorizationServerMetadata.Builder metadata) {
        metadata.grantTypes(AuthorizationServerConfig::replaceAdvertisedGrantTypes);
        metadata.tokenEndpointAuthenticationMethods(
                AuthorizationServerConfig::includePublicClientAuthentication);
    }

    private static void customizeAdvertisedCapabilities(OidcProviderConfiguration.Builder metadata) {
        metadata.grantTypes(AuthorizationServerConfig::replaceAdvertisedGrantTypes);
        metadata.tokenEndpointAuthenticationMethods(
                AuthorizationServerConfig::includePublicClientAuthentication);
    }

    private static void replaceAdvertisedGrantTypes(List<String> grantTypes) {
        grantTypes.clear();
        grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN.getValue());
    }

    private static void includePublicClientAuthentication(List<String> authenticationMethods) {
        authenticationMethods.add(ClientAuthenticationMethod.NONE.getValue());
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
                                                           RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(UnifiedLoginProperties properties) {
        String keyStore = Objects.requireNonNull(properties.jwtKeyStore(),
                "unified-login.jwt-key-store 未配置");
        RSAKey rsaKey = RsaKeyProvider.loadOrCreate(Path.of(keyStore));
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(UnifiedLoginProperties properties) {
        // issuer 必须来自配置（ISSUER_URL）：写死在代码里的话，部署到任何非本地
        // 环境都会在 discovery 与 JWT 的 iss 里广播错误地址
        return AuthorizationServerSettings.builder()
                .issuer(Objects.requireNonNull(properties.issuer(), "unified-login.issuer 未配置"))
                .build();
    }
}
