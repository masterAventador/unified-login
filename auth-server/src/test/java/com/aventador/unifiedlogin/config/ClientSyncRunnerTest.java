package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
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

    @Test
    void demoWebAIsRegisteredFromConfiguration() {
        RegisteredClient client = registeredClientRepository.findByClientId("demo-web-a");

        assertThat(client).isNotNull();
        assertThat(client.getRedirectUris()).contains("http://localhost:5173/callback");
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
}
