package com.aventador.unifiedlogin.security;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class LoginAttemptEventListener {

    private final LoginAttemptService loginAttemptService;

    public LoginAttemptEventListener(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    /**
     * 订阅失败事件的父类型而不是 BadCredentials 一种。
     *
     * <p>账号不存在时 DaoAuthenticationProvider 会把 UsernameNotFoundException 转成
     * BadCredentialsException（默认 hideUserNotFoundExceptions=true），但账号被禁用、
     * 被锁、已过期走的是 DisabledException 等独立异常，框架会映射成各自的事件。
     * 只订 BadCredentials 会让这些账号一次都不计数——攻击者据此就能把「真实存在但已禁用」
     * 从其余情况里认出来，正好复活了本功能要消除的那个预言机。
     */
    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        if (isInfrastructureFailure(event)) {
            return;
        }
        loginAttemptService.recordFailure(event.getAuthentication().getName());
    }

    /**
     * 基础设施故障不计数。数据库连不上时每一次登录都会失败，若照单全收，
     * 一次故障就能把所有正在登录的正常用户批量锁死十五分钟，把可用性事故放大成账号事故。
     */
    private static boolean isInfrastructureFailure(AbstractAuthenticationFailureEvent event) {
        return event instanceof AuthenticationFailureServiceExceptionEvent
                || event instanceof AuthenticationFailureProviderNotFoundEvent;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        loginAttemptService.clearFailures(event.getAuthentication().getName());
    }
}
