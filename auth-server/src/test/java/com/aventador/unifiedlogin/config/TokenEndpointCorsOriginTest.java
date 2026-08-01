package com.aventador.unifiedlogin.config;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class TokenEndpointCorsOriginTest {

    @Test
    void onlyHttpAndHttpsRedirectsBecomeBrowserCorsOrigins() {
        UnifiedLoginProperties properties = new UnifiedLoginProperties(
                "http://localhost:9000",
                "./data/key.json",
                List.of(
                        new UnifiedLoginProperties.ClientConfig(
                                "mixed-client",
                                "Mixed Client",
                                List.of(
                                        "myapp://callback",
                                        "http://127.0.0.1/callback",
                                        "https://desktop.example.com/callback"),
                                null),
                        new UnifiedLoginProperties.ClientConfig(
                                "hostless-client",
                                "Hostless Client",
                                List.of("file:///tmp/callback"),
                                null)),
                null);

        assertThat(TokenEndpointCorsConfig.registeredClientOrigins(properties))
                .containsExactlyInAnyOrder(
                        "http://127.0.0.1",
                        "https://desktop.example.com");
    }
}
