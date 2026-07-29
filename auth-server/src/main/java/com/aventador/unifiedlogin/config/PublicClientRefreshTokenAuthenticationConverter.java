package com.aventador.unifiedlogin.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * 让公有客户端能通过刷新请求的客户端认证。
 *
 * <p>框架内置的转换器覆盖不到这个场景：{@code PublicClientAuthenticationConverter}
 * 要求「authorization_code + 带 code_verifier」，其余转换器都要求密钥、证书或断言，
 * 公有客户端一个也用不上，刷新请求因此无法通过客户端认证。详见规格书 §6.3。
 *
 * <p><b>必须严格限定适用范围</b>：只认 grant_type=refresh_token 且不带 client_secret
 * 的请求，绝不能抢走授权码流程的客户端认证——否则会绕过 code_verifier 校验。
 */
final class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {

    private final RequestMatcher tokenEndpointMatcher;

    PublicClientRefreshTokenAuthenticationConverter(AuthorizationServerSettings settings) {
        this.tokenEndpointMatcher =
                PathPatternRequestMatcher.pathPattern(HttpMethod.POST, settings.getTokenEndpoint());
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        // 必须先限定端点：客户端认证过滤器同时覆盖 token、introspect、revoke 等多个端点，
        // 且自定义转换器被插在内置转换器最前面。不限定端点的话，任何人带上公开的 client_id
        // 再加一个与内省毫无关系的 grant_type=refresh_token，就能通过 introspect 读出令牌里的
        // sub 与 email，或通过 revoke 撤销他人令牌。
        if (!tokenEndpointMatcher.matches(request)) {
            return null;
        }

        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
            return null;
        }
        // 带密钥的请求交给框架自己的转换器，这里只处理公有客户端
        if (request.getParameter(OAuth2ParameterNames.CLIENT_SECRET) != null) {
            return null;
        }
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId)) {
            return null;
        }

        // 把 grant_type 放进附加参数，供 provider 二次确认来源，避免误处理其他流程的令牌
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.GRANT_TYPE, grantType);

        return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null,
                additionalParameters);
    }
}
