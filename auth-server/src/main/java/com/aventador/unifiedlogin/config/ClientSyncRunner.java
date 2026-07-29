package com.aventador.unifiedlogin.config;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Configuration
@EnableConfigurationProperties(UnifiedLoginProperties.class)
public class ClientSyncRunner {

    private static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(15);
    private static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(30);

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /**
     * 幂等同步：已存在的 client 沿用原 id 重建后 save（save 以 id 为主键更新）。
     * 注意：配置中移除某个 client 不会删除库中已注册的行及其回调白名单，
     * 需手动清理——与 bootstrap.admin-emails 的撤销语义一致。
     */
    @Bean
    public ApplicationRunner syncRegisteredClients(RegisteredClientRepository repository,
                                                   UnifiedLoginProperties properties) {
        return (args) -> {
            // record 构造器绑定在配置节点缺失时得到 null 而非空列表，这里显式归一
            List<UnifiedLoginProperties.ClientConfig> clients =
                    Objects.requireNonNullElseGet(properties.clients(), List::of);
            for (UnifiedLoginProperties.ClientConfig config : clients) {
                RegisteredClient existing = repository.findByClientId(config.clientId());
                String id = (existing != null) ? existing.getId() : UUID.randomUUID().toString();
                repository.save(build(id, config));
            }
        };
    }

    private static RegisteredClient build(String id, UnifiedLoginProperties.ClientConfig config) {
        RegisteredClient.Builder builder = RegisteredClient.withId(id)
                .clientId(config.clientId())
                .clientName(config.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(ACCESS_TOKEN_TTL)
                        .refreshTokenTimeToLive(REFRESH_TOKEN_TTL)
                        .reuseRefreshTokens(false)
                        .build());

        List<String> redirectUris = config.redirectUris();
        if (redirectUris == null || redirectUris.isEmpty()) {
            throw new IllegalStateException("客户端 " + config.clientId() + " 未配置 redirect-uris，回调白名单不能为空");
        }
        redirectUris.forEach(builder::redirectUri);

        return builder.build();
    }
}
