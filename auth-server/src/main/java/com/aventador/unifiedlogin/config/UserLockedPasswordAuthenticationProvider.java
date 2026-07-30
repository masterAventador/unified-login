package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.account.UserTokenLock;
import com.aventador.unifiedlogin.user.EmailAddress;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 用用户行锁串行化表单密码校验与所有密码替换操作。
 *
 * <p>只在读取用户之后补查密码版本仍然有竞态：登录可先读旧 hash，等改密提交后再完成校验，
 * 从而得到一个认证时间晚于改密时间的旧密码会话。这里把行锁覆盖到整个
 * {@link DaoAuthenticationProvider} 调用，保证旧密码登录只能完整发生在改密之前，或在改密之后
 * 读取新 hash 并失败。
 */
final class UserLockedPasswordAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationProvider delegate;

    private final UserTokenLock userTokenLock;

    private final TransactionTemplate transactionTemplate;

    UserLockedPasswordAuthenticationProvider(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder,
            UserTokenLock userTokenLock,
            PlatformTransactionManager transactionManager) {
        DaoAuthenticationProvider delegate = new DaoAuthenticationProvider(userDetailsService);
        delegate.setPasswordEncoder(passwordEncoder);
        this.delegate = delegate;
        this.userTokenLock = userTokenLock;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return this.transactionTemplate.execute((status) -> {
            this.userTokenLock.lockByPrincipalName(
                    EmailAddress.normalize(authentication.getName()));
            return this.delegate.authenticate(authentication);
        });
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return this.delegate.supports(authentication);
    }
}
