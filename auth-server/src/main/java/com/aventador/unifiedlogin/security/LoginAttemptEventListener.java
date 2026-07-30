package com.aventador.unifiedlogin.security;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
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
        if (isInfrastructureFailure(event) || !isFormLogin(event.getAuthentication())) {
            return;
        }
        loginAttemptService.recordFailure(event.getAuthentication().getName());
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        if (!isFormLogin(event.getAuthentication())) {
            return;
        }
        loginAttemptService.clearFailures(event.getAuthentication().getName());
    }

    /**
     * 基础设施故障不计数。数据库连不上时每一次登录都会失败，若照单全收，
     * 一次故障就能把所有正在登录的正常用户批量锁死十五分钟，把可用性事故放大成账号事故。
     */
    private static boolean isInfrastructureFailure(AbstractAuthenticationFailureEvent event) {
        return event instanceof AuthenticationFailureServiceExceptionEvent
                || event instanceof AuthenticationFailureProviderNotFoundEvent;
    }

    /**
     * 只有表单登录才该动登录限流计数。
     *
     * <p>资源服务器校验 Bearer token 失败时抛的是 InvalidBearerTokenException，同样被映射成
     * BadCredentials 事件，而它的主体是 BearerTokenAuthenticationToken，{@code getName()} 直接返回
     * token 字符串。若照单计数，攻击者拿随机 token 猛打 /userinfo 就能往邮箱计数表里塞满垃圾键，
     * 靠 maximumSize 淘汰把某个真实邮箱已生效的锁定记录挤出去，锁定随之消失——一条锁定绕过路径。
     *
     * <p>按令牌类型过滤是精确的：表单登录无论成功、密码错误、账号不存在还是账号被禁用，
     * 主体都是 UsernamePasswordAuthenticationToken；而客户端认证、Bearer token 校验都不是。
     */
    private static boolean isFormLogin(Authentication authentication) {
        return authentication instanceof UsernamePasswordAuthenticationToken;
    }
}
