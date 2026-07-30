package com.aventador.unifiedlogin.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
/**
 * Enforces OIDC {@code prompt=login} for authorization-code requests.
 *
 * <p>Spring Authorization Server 7.1 validates the parameter but does not
 * challenge an already authenticated principal. The marker allows the exact
 * saved request through once after form login; without it, the restored
 * authorization request would clear the new session again and loop forever.
 */
final class PromptLoginAuthenticationFilter extends OncePerRequestFilter {

    private static final String REAUTHENTICATION_REQUEST =
            PromptLoginAuthenticationFilter.class.getName() + ".request";

    private final String authorizationEndpoint;

    PromptLoginAuthenticationFilter(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        if (!requiresReauthentication(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        HttpSession session = request.getSession();
        String requestFingerprint = requestFingerprint(request);
        if (requestFingerprint.equals(session.getAttribute(REAUTHENTICATION_REQUEST))) {
            session.removeAttribute(REAUTHENTICATION_REQUEST);
            filterChain.doFilter(request, response);
            return;
        }

        session.setAttribute(REAUTHENTICATION_REQUEST, requestFingerprint);
        session.removeAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        SecurityContextHolder.clearContext();
        filterChain.doFilter(request, response);
    }

    private boolean requiresReauthentication(HttpServletRequest request) {
        String requestPath = request.getRequestURI().substring(request.getContextPath().length());
        return "GET".equals(request.getMethod())
                && authorizationEndpoint.equals(requestPath)
                && "login".equals(request.getParameter("prompt"));
    }

    private String requestFingerprint(HttpServletRequest request) {
        return String.join("\u0000",
                valueOrEmpty(request.getParameter("client_id")),
                valueOrEmpty(request.getParameter("state")),
                valueOrEmpty(request.getParameter("redirect_uri")),
                valueOrEmpty(request.getParameter("code_challenge")));
    }

    private String valueOrEmpty(String value) {
        return value == null ? "" : value;
    }
}
