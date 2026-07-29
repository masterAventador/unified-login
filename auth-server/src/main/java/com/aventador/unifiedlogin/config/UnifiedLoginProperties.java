package com.aventador.unifiedlogin.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "unified-login")
public record UnifiedLoginProperties(String issuer, String jwtKeyStore, List<ClientConfig> clients) {

    public record ClientConfig(String clientId, String clientName, List<String> redirectUris) {
    }
}
