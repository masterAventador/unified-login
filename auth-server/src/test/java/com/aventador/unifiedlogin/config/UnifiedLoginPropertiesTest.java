package com.aventador.unifiedlogin.config;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class UnifiedLoginPropertiesTest {

    @Test
    void clientScopesAreConfigurableAndDefaultToOpenid() {
        UnifiedLoginProperties.ClientConfig configured = new UnifiedLoginProperties.ClientConfig(
                "desktop",
                "Desktop",
                List.of("http://127.0.0.1/callback"),
                List.of("openid", "profile", "email"));
        UnifiedLoginProperties.ClientConfig omitted = new UnifiedLoginProperties.ClientConfig(
                "web",
                "Web",
                List.of("http://localhost/callback"),
                null);
        UnifiedLoginProperties.ClientConfig missingOpenid = new UnifiedLoginProperties.ClientConfig(
                "desktop-with-incomplete-scopes",
                "Desktop",
                List.of("http://127.0.0.1/callback"),
                List.of("profile", "email"));

        assertThat(configured.scopesOrDefault()).containsExactly("openid", "profile", "email");
        assertThat(omitted.scopesOrDefault()).containsExactly("openid");
        assertThat(missingOpenid.scopesOrDefault()).containsExactly("openid", "profile", "email");
    }
}
