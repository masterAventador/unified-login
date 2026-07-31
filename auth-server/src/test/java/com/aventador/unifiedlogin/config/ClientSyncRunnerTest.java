package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Import(PostgresTestConfig.class)
class ClientSyncRunnerTest {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    @Qualifier("syncRegisteredClients")
    private ApplicationRunner syncRunner;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void demoWebAIsRegisteredFromConfiguration() {
        RegisteredClient client = registeredClientRepository.findByClientId("demo-web-a");

        assertThat(client).isNotNull();
        assertThat(client.getRedirectUris()).contains("http://localhost:5173/callback");
    }

    @Test
    void adminWebIsRegisteredFromConfiguration() {
        RegisteredClient client = registeredClientRepository.findByClientId("admin-web");

        assertThat(client).isNotNull();
        assertThat(client.getRedirectUris()).containsExactly("http://localhost:5175/callback");
        assertThat(client.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
    }

    @Test
    void desktopClientRegistersPortlessLoopbackRedirectForEphemeralPorts() {
        RegisteredClient client = registeredClientRepository.findByClientId("demo-desktop");

        assertThat(client).isNotNull();
        assertThat(client.getRedirectUris()).containsExactly("http://127.0.0.1/callback");
        assertThat(client.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
    }

    @Test
    void clientIsPublicAndRequiresPkce() {
        RegisteredClient client = registeredClientRepository.findByClientId("demo-web-a");

        assertThat(client.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getClientSettings().isRequireAuthorizationConsent()).isFalse();
    }

    @Test
    void clientSupportsAuthorizationCodeAndRefreshTokenOnly() {
        RegisteredClient client = registeredClientRepository.findByClientId("demo-web-a");

        assertThat(client.getAuthorizationGrantTypes())
                .containsExactlyInAnyOrder(AuthorizationGrantType.AUTHORIZATION_CODE,
                        AuthorizationGrantType.REFRESH_TOKEN);
    }

    @Test
    void tokenLifetimesMatchSpecification() {
        RegisteredClient client = registeredClientRepository.findByClientId("demo-web-a");

        assertThat(client.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(15));
        assertThat(client.getTokenSettings().getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(30));
        assertThat(client.getTokenSettings().isReuseRefreshTokens()).isFalse();
    }

    @Test
    void unknownClientIsNotRegistered() {
        assertThat(registeredClientRepository.findByClientId("never-configured")).isNull();
    }

    @Test
    void syncIsIdempotentAcrossRestarts() throws Exception {
        RegisteredClient before = registeredClientRepository.findByClientId("demo-web-a");

        // 手动再执行一次启动同步，模拟应用重启（上下文缓存不会自动重跑 ApplicationRunner）
        syncRunner.run(null);

        RegisteredClient after = registeredClientRepository.findByClientId("demo-web-a");
        assertThat(after.getId()).isEqualTo(before.getId());
        assertThat(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM oauth2_registered_client WHERE client_id = 'demo-web-a'",
                Integer.class)).isEqualTo(1);
    }
}
