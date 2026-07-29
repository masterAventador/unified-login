package com.aventador.unifiedlogin.security;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class LoginAttemptEventListener {

    private final LoginAttemptService loginAttemptService;

    public LoginAttemptEventListener(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    /**
     * 账号不存在时 DaoAuthenticationProvider 会把 UsernameNotFoundException 转成
     * BadCredentialsException（默认 hideUserNotFoundExceptions=true），因此这里天然
     * 对不存在的邮箱也会计数——正是防枚举所需要的。
     */
    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {
        loginAttemptService.recordFailure(event.getAuthentication().getName());
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        loginAttemptService.clearFailures(event.getAuthentication().getName());
    }
}
