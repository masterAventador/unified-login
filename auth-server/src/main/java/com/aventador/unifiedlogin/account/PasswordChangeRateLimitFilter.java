package com.aventador.unifiedlogin.account;

import com.aventador.unifiedlogin.security.LoginAttemptService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class PasswordChangeRateLimitFilter extends OncePerRequestFilter {

    private static final RequestMatcher PASSWORD_CHANGE_SUBMISSION =
            PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/account/password");

    private static final String TOO_MANY_ATTEMPTS_MESSAGE = "密码验证尝试过于频繁，请稍后再试";

    private final LoginAttemptService loginAttemptService;

    public PasswordChangeRateLimitFilter(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (loginAttemptService.registerAttemptAndCheckRateLimit(request.getRemoteAddr())
                || authentication != null && loginAttemptService.isLocked(authentication.getName())) {
            response.sendError(HttpStatus.TOO_MANY_REQUESTS.value(), TOO_MANY_ATTEMPTS_MESSAGE);
            return;
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !PASSWORD_CHANGE_SUBMISSION.matches(request);
    }
}
