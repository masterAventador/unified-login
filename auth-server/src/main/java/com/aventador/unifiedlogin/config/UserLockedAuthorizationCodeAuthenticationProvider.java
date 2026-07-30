package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.account.UserTokenLock;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 用用户行锁串行化授权码兑换与密码变更 / 全量令牌撤销。
 *
 * <p>只在 JWT customizer 中回查 {@code password_changed_at} 仍不够：回查通过以后，
 * 框架还要生成令牌并最终保存授权。并发改密若恰好落在回查和保存之间，就可能先删除旧授权，
 * 随后又被框架保存回来，甚至把刚生成的 access token 返回给客户端。这里包住框架的完整
 * authorization-code provider，让查找授权、账号回查、令牌生成和最终保存全都处于同一个
 * 数据库事务和同一把用户行锁内。
 */
final class UserLockedAuthorizationCodeAuthenticationProvider implements AuthenticationProvider {

    private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE =
            new OAuth2TokenType(OAuth2ParameterNames.CODE);

    private final AuthenticationProvider delegate;

    private final OAuth2AuthorizationService authorizationService;

    private final UserTokenLock userTokenLock;

    private final TransactionTemplate transactionTemplate;

    private UserLockedAuthorizationCodeAuthenticationProvider(
            AuthenticationProvider delegate,
            OAuth2AuthorizationService authorizationService,
            UserTokenLock userTokenLock,
            PlatformTransactionManager transactionManager) {
        this.delegate = delegate;
        this.authorizationService = authorizationService;
        this.userTokenLock = userTokenLock;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    static void guardAuthorizationCodeProvider(
            List<AuthenticationProvider> providers,
            OAuth2AuthorizationService authorizationService,
            UserTokenLock userTokenLock,
            PlatformTransactionManager transactionManager) {
        int guarded = 0;
        for (int i = 0; i < providers.size(); i++) {
            if (providers.get(i) instanceof OAuth2AuthorizationCodeAuthenticationProvider) {
                providers.set(i, new UserLockedAuthorizationCodeAuthenticationProvider(
                        providers.get(i), authorizationService, userTokenLock, transactionManager));
                guarded++;
            }
        }
        if (guarded != 1) {
            throw new IllegalStateException("令牌端点应恰好有一个 "
                    + OAuth2AuthorizationCodeAuthenticationProvider.class.getSimpleName()
                    + " 可供包裹，实际找到 " + guarded + " 个；授权码兑换与账号失效操作无法串行化，拒绝启动");
        }
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AtomicReference<AuthenticationException> authenticationFailure = new AtomicReference<>();
        Authentication result = this.transactionTemplate.execute((transactionStatus) -> {
            try {
                return authenticateWithinTransaction(authentication);
            }
            catch (AuthenticationException ex) {
                // 框架在检测到授权码重放时，会先把此前用该码换出的 access / refresh token
                // 标为失效，再抛 invalid_grant。若让异常直接越过 TransactionTemplate，那次
                // 安全性更新会被回滚，泄漏的 refresh token 仍能继续使用。因此认证失败要在
                // 事务提交之后再向过滤器链抛出。
                authenticationFailure.set(ex);
                return null;
            }
        });
        if (authenticationFailure.get() != null) {
            throw authenticationFailure.get();
        }
        return result;
    }

    private Authentication authenticateWithinTransaction(Authentication authentication) {
        OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication =
                (OAuth2AuthorizationCodeAuthenticationToken) authentication;
        OAuth2Authorization authorization = this.authorizationService.findByToken(
                authorizationCodeAuthentication.getCode(), AUTHORIZATION_CODE_TOKEN_TYPE);
        if (authorization != null
                && !this.userTokenLock.lockByPrincipalName(authorization.getPrincipalName())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        return this.delegate.authenticate(authentication);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return this.delegate.supports(authentication);
    }
}
