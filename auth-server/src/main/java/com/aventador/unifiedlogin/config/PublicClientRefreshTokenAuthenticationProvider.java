package com.aventador.unifiedlogin.config;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.Map;

/**
 * 校验 {@link PublicClientRefreshTokenAuthenticationConverter} 造出的客户端认证令牌。
 *
 * <p>公有客户端没有任何客户端凭证可供校验，这里能做的是确认「该客户端确实注册过、
 * 确实是公有客户端、确实允许刷新授权」。刷新请求的真正凭证是 refresh token 本身，
 * 由框架的刷新授权流程校验，其安全性靠一次性轮转保障。
 */
final class PublicClientRefreshTokenAuthenticationProvider implements AuthenticationProvider {

    private final RegisteredClientRepository registeredClientRepository;

    PublicClientRefreshTokenAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;

        // 返回 null 表示「本 provider 不处理」，认证链会继续交给框架自己的 provider。
        // 这两道判断保证只接手上面那个转换器造出来的刷新请求，不影响授权码流程。
        if (!ClientAuthenticationMethod.NONE.equals(clientAuthentication.getClientAuthenticationMethod())) {
            return null;
        }
        Map<String, Object> additionalParameters = clientAuthentication.getAdditionalParameters();
        if (additionalParameters == null || !AuthorizationGrantType.REFRESH_TOKEN.getValue()
                .equals(additionalParameters.get(OAuth2ParameterNames.GRANT_TYPE))) {
            return null;
        }

        RegisteredClient registeredClient =
                registeredClientRepository.findByClientId((String) clientAuthentication.getPrincipal());
        if (registeredClient == null
                || !registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)
                || !registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        return new OAuth2ClientAuthenticationToken(registeredClient, ClientAuthenticationMethod.NONE, null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
