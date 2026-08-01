package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.account.TokenRevocationService;
import com.aventador.unifiedlogin.account.UsedRefreshTokenStore;
import com.aventador.unifiedlogin.account.UserTokenLock;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * 让账号状态管住 refresh token 授权。
 *
 * <p>刷新授权用的是首次登录时序列化进 {@code oauth2_authorization.attributes} 的 principal 快照，
 * 框架从不回查用户表；而本系统启用了一次性轮转，每次刷新都签发一把新的 30 天令牌。两者叠加
 * 的后果是被禁用的账号只要保持活跃就**永远不会失效**。规格书 §10 要求「账号已禁用 → 持有的
 * refresh token 也无法换取新 token」，这里补上那道回查。
 *
 * <p><b>为什么是包住框架 provider，而不是在它前面另加一个 provider</b>：{@code ProviderManager}
 * 只对 {@code AccountStatusException} 与 {@code InternalAuthenticationServiceException} 立即中断，
 * 其余 {@code AuthenticationException} 只是记进 {@code lastException} 然后**继续遍历**，并在任一
 * provider 返回非 null 时直接判定成功。因此新加的 provider 即使排在最前面并抛出 invalid_grant，
 * 框架自带的 {@link OAuth2RefreshTokenAuthenticationProvider} 随后照样会签发令牌——已实测确认
 * 这么写完全没有效果（禁用账号仍返回 200 与全新令牌）。要真正否决，就必须站在框架 provider
 * 与调用方之间，即取代它在 provider 列表中的位置。
 */
final class AccountStatusRefreshTokenAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationProvider delegate;

    private final OAuth2AuthorizationService authorizationService;

    private final UserDetailsService userDetailsService;

    private final UserTokenLock userTokenLock;

    private final UsedRefreshTokenStore usedRefreshTokenStore;

    private final TokenRevocationService tokenRevocationService;

    private final TransactionTemplate transactionTemplate;

    private AccountStatusRefreshTokenAuthenticationProvider(AuthenticationProvider delegate,
            OAuth2AuthorizationService authorizationService, UserDetailsService userDetailsService,
            UserTokenLock userTokenLock, UsedRefreshTokenStore usedRefreshTokenStore,
            TokenRevocationService tokenRevocationService, PlatformTransactionManager transactionManager) {
        this.delegate = delegate;
        this.authorizationService = authorizationService;
        this.userDetailsService = userDetailsService;
        this.userTokenLock = userTokenLock;
        this.usedRefreshTokenStore = usedRefreshTokenStore;
        this.tokenRevocationService = tokenRevocationService;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    /**
     * 把令牌端点默认 provider 列表里的刷新 provider 换成带账号状态回查的版本。
     *
     * <p>找不到可包的目标时**直接让应用启动失败**：框架升级若改名或移除了这个 provider，
     * 静默跳过的后果是这道安全检查凭空消失，而所有测试仍然全绿——本项目已经在别处栽过
     * 「保护写了但没人守着」的跟头，这里必须响。
     */
    static void guardRefreshTokenProvider(List<AuthenticationProvider> providers,
            OAuth2AuthorizationService authorizationService, UserDetailsService userDetailsService,
            UserTokenLock userTokenLock, UsedRefreshTokenStore usedRefreshTokenStore,
            TokenRevocationService tokenRevocationService, PlatformTransactionManager transactionManager) {
        int guarded = 0;
        for (int i = 0; i < providers.size(); i++) {
            if (providers.get(i) instanceof OAuth2RefreshTokenAuthenticationProvider) {
                providers.set(i, new AccountStatusRefreshTokenAuthenticationProvider(
                        providers.get(i), authorizationService, userDetailsService,
                        userTokenLock, usedRefreshTokenStore, tokenRevocationService, transactionManager));
                guarded++;
            }
        }
        if (guarded != 1) {
            throw new IllegalStateException("令牌端点应恰好有一个 "
                    + OAuth2RefreshTokenAuthenticationProvider.class.getSimpleName()
                    + " 可供包裹，实际找到 " + guarded + " 个；账号状态回查将失效，拒绝启动");
        }
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        RefreshResult result = Objects.requireNonNull(this.transactionTemplate.execute(
                (transactionStatus) -> authenticateWithinTransaction(authentication)));
        if (result.replayDetected()) {
            // 必须在撤销事务提交之后再抛异常，否则 TransactionTemplate 会把 DELETE 一起回滚。
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        return result.authentication();
    }

    private RefreshResult authenticateWithinTransaction(Authentication authentication) {
        OAuth2RefreshTokenAuthenticationToken refreshTokenAuthentication =
                (OAuth2RefreshTokenAuthenticationToken) authentication;
        String refreshToken = refreshTokenAuthentication.getRefreshToken();

        Optional<UUID> replayedUserId = this.usedRefreshTokenStore.findUnexpiredUserId(refreshToken);
        if (replayedUserId.isPresent()) {
            this.tokenRevocationService.revokeAllTokensOf(replayedUserId.get());
            return RefreshResult.replay();
        }

        OAuth2Authorization authorization = this.authorizationService
                .findByToken(refreshToken, OAuth2TokenType.REFRESH_TOKEN);
        // 令牌本身查不到授权记录时这里无从判断账号，也不需要判断：交给被包裹的 provider
        // 按 invalid_grant 拒绝，保持「令牌无效」与「账号不可用」的响应形态一致
        if (authorization != null) {
            // 必须在回查状态和框架保存轮转结果之前取得用户行锁，并由包住整个 delegate
            // 的事务持有到 save 完成。否则并发撤销可能先 DELETE，随后被 save 重新 INSERT。
            Optional<UUID> userId = this.userTokenLock
                    .lockAndGetUserIdByPrincipalName(authorization.getPrincipalName());
            if (userId.isEmpty()) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }

            // 两个请求可能都在取得用户锁前读到旧授权。后到者必须在锁内重查消费记录，
            // 才能把并发的第二次提交识别为重放，而不是只让框架返回普通 invalid_grant。
            replayedUserId = this.usedRefreshTokenStore.findUnexpiredUserId(refreshToken);
            if (replayedUserId.isPresent()) {
                this.tokenRevocationService.revokeAllTokensOf(replayedUserId.get());
                return RefreshResult.replay();
            }
            requireUsableAccount(authorization.getPrincipalName());

            Authentication authenticated = this.delegate.authenticate(authentication);
            this.usedRefreshTokenStore.record(refreshToken, userId.get(),
                    Objects.requireNonNull(authorization.getRefreshToken().getToken().getExpiresAt(),
                            "持久化的刷新令牌必须有过期时间"));
            return RefreshResult.success(authenticated);
        }
        return RefreshResult.success(this.delegate.authenticate(authentication));
    }

    /**
     * 「账号是否还能用」只有一个判据，就是登录链路用的那个。走 {@link UserDetailsService}
     * 而不是自己查一遍状态字段，是为了让将来新增的账号状态（锁定、过期等）自动同时管住
     * 登录与续期两条路径，不会出现只堵住其中一条的情况。
     */
    private void requireUsableAccount(String principalName) {
        UserDetails userDetails;
        try {
            userDetails = this.userDetailsService.loadUserByUsername(principalName);
        }
        catch (UsernameNotFoundException ex) {
            // 账号在 refresh token 有效期内被删除
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        if (!userDetails.isEnabled()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return this.delegate.supports(authentication);
    }

    private record RefreshResult(Authentication authentication, boolean replayDetected) {

        private static RefreshResult success(Authentication authentication) {
            return new RefreshResult(authentication, false);
        }

        private static RefreshResult replay() {
            return new RefreshResult(null, true);
        }
    }
}
