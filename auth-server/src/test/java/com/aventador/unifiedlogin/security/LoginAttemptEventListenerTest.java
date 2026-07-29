package com.aventador.unifiedlogin.security;

import com.aventador.unifiedlogin.support.MutableTicker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 守着监听器的两条过滤规则：哪些失败该计数、哪些不该。
 *
 * <p>阈值特意设成 1，一次事件就足以体现「计没计数」，断言不必绕圈。
 */
class LoginAttemptEventListenerTest {

    private static final String EMAIL = "user@example.com";
    private static final String BEARER_TOKEN = "definitely-not-a-jwt";

    private LoginAttemptService service;
    private LoginAttemptEventListener listener;

    @BeforeEach
    void setUp() {
        service = new LoginAttemptService(new LoginRateLimitProperties(1, Duration.ofMinutes(15), 20),
                new MutableTicker());
        listener = new LoginAttemptEventListener(service);
    }

    @Test
    void countsBadCredentialsFailure() {
        listener.onFailure(new AuthenticationFailureBadCredentialsEvent(formLogin(),
                new BadCredentialsException("邮箱或密码不正确")));

        assertThat(service.isLocked(EMAIL)).isTrue();
    }

    @Test
    void countsDisabledAccountFailure() {
        listener.onFailure(new AuthenticationFailureDisabledEvent(formLogin(),
                new DisabledException("账号已禁用")));

        assertThat(service.isLocked(EMAIL)).isTrue();
    }

    @Test
    void countsLockedAccountFailure() {
        listener.onFailure(new AuthenticationFailureLockedEvent(formLogin(),
                new LockedException("账号已锁定")));

        assertThat(service.isLocked(EMAIL)).isTrue();
    }

    @Test
    void ignoresServiceExceptionFailure() {
        // 数据库故障会让所有登录同时失败，若计数就会把正常用户批量锁死
        listener.onFailure(new AuthenticationFailureServiceExceptionEvent(formLogin(),
                new AuthenticationServiceException("数据库连接失败")));

        assertThat(service.isLocked(EMAIL)).isFalse();
    }

    @Test
    void ignoresProviderNotFoundFailure() {
        // 同上，属于配置或基础设施问题而非用户的凭据问题
        listener.onFailure(new AuthenticationFailureProviderNotFoundEvent(formLogin(),
                new ProviderNotFoundException("没有可用的认证提供方")));

        assertThat(service.isLocked(EMAIL)).isFalse();
    }

    @Test
    void ignoresBearerTokenFailureSoItCannotEvictRealLockouts() {
        // 坏 token 的失败也映射成 BadCredentials 事件，但主体是 BearerTokenAuthenticationToken，
        // getName() 返回 token 字符串本身。若计数，攻击者刷随机 token 就能把真实邮箱的锁定记录挤出缓存
        listener.onFailure(new AuthenticationFailureBadCredentialsEvent(
                new BearerTokenAuthenticationToken(BEARER_TOKEN),
                new BadCredentialsException("token 无效")));

        assertThat(service.isLocked(BEARER_TOKEN)).isFalse();
    }

    @Test
    void clearsCountOnFormLoginSuccess() {
        listener.onFailure(new AuthenticationFailureBadCredentialsEvent(formLogin(),
                new BadCredentialsException("邮箱或密码不正确")));
        assertThat(service.isLocked(EMAIL)).isTrue();

        listener.onSuccess(new AuthenticationSuccessEvent(formLogin()));

        assertThat(service.isLocked(EMAIL)).isFalse();
    }

    @Test
    void bearerTokenSuccessDoesNotClearAnybodyLockout() {
        listener.onFailure(new AuthenticationFailureBadCredentialsEvent(formLogin(),
                new BadCredentialsException("邮箱或密码不正确")));

        listener.onSuccess(new AuthenticationSuccessEvent(new BearerTokenAuthenticationToken(EMAIL)));

        assertThat(service.isLocked(EMAIL)).isTrue();
    }

    private static Authentication formLogin() {
        return UsernamePasswordAuthenticationToken.unauthenticated(EMAIL, "任意密码");
    }
}
