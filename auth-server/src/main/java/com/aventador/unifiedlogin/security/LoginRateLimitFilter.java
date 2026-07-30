package com.aventador.unifiedlogin.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 在认证之前挡下超限的登录提交。
 *
 * <p>放在认证之前有两层作用：被锁的账号不再触发一次 Argon2id 运算，省下算力；
 * 被锁期间的尝试也不再计入失败次数，否则持续敲门会把锁定期无限延长。
 */
public class LoginRateLimitFilter extends OncePerRequestFilter {

    private static final RequestMatcher LOGIN_SUBMISSION = PathPatternRequestMatcher.withDefaults()
            .matcher(HttpMethod.POST, LoginPaths.LOGIN);

    private static final String TOO_MANY_ATTEMPTS_MESSAGE = "登录尝试过于频繁，请稍后再试";

    private final LoginAttemptService loginAttemptService;

    public LoginRateLimitFilter(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // 只认 getRemoteAddr()：X-Forwarded-For 是客户端可随意伪造的请求头，
        // 在没有可信反向代理并显式配置的前提下采信它，等于把限流开关交给攻击者
        if (loginAttemptService.registerAttemptAndCheckRateLimit(request.getRemoteAddr())) {
            response.sendError(HttpStatus.TOO_MANY_REQUESTS.value(), TOO_MANY_ATTEMPTS_MESSAGE);
            return;
        }

        // 不存在与格式非法的邮箱同样会被锁，因此这里不需要（也不该）区分账号是否真实存在
        if (loginAttemptService.isLocked(request.getParameter(
                UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY))) {
            response.sendRedirect(request.getContextPath() + LoginPaths.LOCKED_REDIRECT);
            return;
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !LOGIN_SUBMISSION.matches(request);
    }
}
