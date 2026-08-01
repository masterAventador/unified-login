package com.aventador.unifiedlogin.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.core.oidc.OidcScopes;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;

@ConfigurationProperties(prefix = "unified-login")
public record UnifiedLoginProperties(
        String issuer,
        String jwtKeyStore,
        List<ClientConfig> clients,
        BootstrapConfig bootstrap) {

    /**
     * 已配置的接入方，配置节点缺失时返回空列表。
     *
     * <p>record 构造器绑定在配置节点缺失时得到 null 而非空列表，归一逻辑集中在这里，
     * 免得每个用到 clients 的地方各写一份判空。
     */
    public List<ClientConfig> clientsOrEmpty() {
        return Objects.requireNonNullElseGet(clients, List::of);
    }

    public List<String> bootstrapAdminEmailsOrEmpty() {
        if (bootstrap == null) {
            return List.of();
        }
        return Objects.requireNonNullElseGet(bootstrap.adminEmails(), List::of);
    }

    public record ClientConfig(
            String clientId,
            String clientName,
            List<String> redirectUris,
            List<String> scopes) {

        public List<String> scopesOrDefault() {
            if (scopes == null || scopes.isEmpty()) {
                return List.of(OidcScopes.OPENID);
            }
            LinkedHashSet<String> requiredScopes = new LinkedHashSet<>();
            requiredScopes.add(OidcScopes.OPENID);
            requiredScopes.addAll(scopes);
            return List.copyOf(requiredScopes);
        }
    }

    public record BootstrapConfig(List<String> adminEmails) {
    }
}
