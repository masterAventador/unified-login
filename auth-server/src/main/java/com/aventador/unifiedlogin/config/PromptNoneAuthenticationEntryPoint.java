package com.aventador.unifiedlogin.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

final class PromptNoneAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final String PROMPT_PARAMETER = "prompt";

    private static final String PROMPT_NONE = "none";

    private static final String LOGIN_REQUIRED = "login_required";

    private final RegisteredClientRepository registeredClientRepository;

    private final AuthenticationEntryPoint interactiveEntryPoint;

    PromptNoneAuthenticationEntryPoint(RegisteredClientRepository registeredClientRepository,
                                       AuthenticationEntryPoint interactiveEntryPoint) {
        this.registeredClientRepository = registeredClientRepository;
        this.interactiveEntryPoint = interactiveEntryPoint;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authenticationException) throws IOException, ServletException {
        if (!PROMPT_NONE.equals(request.getParameter(PROMPT_PARAMETER))) {
            interactiveEntryPoint.commence(request, response, authenticationException);
            return;
        }

        // Spring Security 7.1 会先经 OAuth2AuthorizationCodeRequestValidatingFilter 校验
        // response_type、PKCE、scope 与 prompt 组合，再进入 AuthorizationFilter 并调用本入口点。
        // 此处仍独立复验 redirect_uri，避免未来过滤器顺序变化时把错误重定向到攻击者地址。
        String redirectUri = registeredRedirectUri(request);
        if (redirectUri == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        UriComponentsBuilder callback = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam(OAuth2ParameterNames.ERROR, LOGIN_REQUIRED);
        String state = request.getParameter(OAuth2ParameterNames.STATE);
        if (state != null) {
            callback.queryParam(OAuth2ParameterNames.STATE, UriUtils.encode(state, StandardCharsets.UTF_8));
        }
        response.sendRedirect(callback.build(true).toUriString());
    }

    private String registeredRedirectUri(HttpServletRequest request) {
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);
        if (clientId == null || redirectUri == null) {
            return null;
        }

        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client == null || !isRegisteredRedirectUri(client, redirectUri)) {
            return null;
        }
        return redirectUri;
    }

    private static boolean isRegisteredRedirectUri(RegisteredClient client, String redirectUri) {
        OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
                new OAuth2AuthorizationCodeRequestAuthenticationToken(
                        "/oauth2/authorize",
                        client.getClientId(),
                        UsernamePasswordAuthenticationToken.unauthenticated("prompt-none", "N/A"),
                        redirectUri,
                        null,
                        Set.of(),
                        Map.of());
        OAuth2AuthorizationCodeRequestAuthenticationContext context =
                OAuth2AuthorizationCodeRequestAuthenticationContext.with(authentication)
                        .registeredClient(client)
                        .build();
        try {
            OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR.accept(context);
            return true;
        } catch (OAuth2AuthorizationCodeRequestAuthenticationException exception) {
            return false;
        }
    }
}
