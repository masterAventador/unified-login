package com.aventador.unifiedlogin.config;

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

import java.util.List;

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

    private AccountStatusRefreshTokenAuthenticationProvider(AuthenticationProvider delegate,
            OAuth2AuthorizationService authorizationService, UserDetailsService userDetailsService) {
        this.delegate = delegate;
        this.authorizationService = authorizationService;
        this.userDetailsService = userDetailsService;
    }

    /**
     * 把令牌端点默认 provider 列表里的刷新 provider 换成带账号状态回查的版本。
     *
     * <p>找不到可包的目标时**直接让应用启动失败**：框架升级若改名或移除了这个 provider，
     * 静默跳过的后果是这道安全检查凭空消失，而所有测试仍然全绿——本项目已经在别处栽过
     * 「保护写了但没人守着」的跟头，这里必须响。
     */
    static void guardRefreshTokenProvider(List<AuthenticationProvider> providers,
            OAuth2AuthorizationService authorizationService, UserDetailsService userDetailsService) {
        int guarded = 0;
        for (int i = 0; i < providers.size(); i++) {
            if (providers.get(i) instanceof OAuth2RefreshTokenAuthenticationProvider) {
                providers.set(i, new AccountStatusRefreshTokenAuthenticationProvider(
                        providers.get(i), authorizationService, userDetailsService));
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
        OAuth2RefreshTokenAuthenticationToken refreshTokenAuthentication =
                (OAuth2RefreshTokenAuthenticationToken) authentication;

        OAuth2Authorization authorization = this.authorizationService
                .findByToken(refreshTokenAuthentication.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
        // 令牌本身查不到授权记录时这里无从判断账号，也不需要判断：交给被包裹的 provider
        // 按 invalid_grant 拒绝，保持「令牌无效」与「账号不可用」的响应形态一致
        if (authorization != null) {
            requireUsableAccount(authorization.getPrincipalName());
        }
        return this.delegate.authenticate(authentication);
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
}
