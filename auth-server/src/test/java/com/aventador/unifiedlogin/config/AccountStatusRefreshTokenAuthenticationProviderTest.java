package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.account.UserTokenLock;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.transaction.PlatformTransactionManager;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

/**
 * 钉住「账号状态回查确实挂上去了」这件事本身。
 *
 * <p>装配逻辑靠的是在框架默认 provider 列表里认出 {@link OAuth2RefreshTokenAuthenticationProvider}
 * 并就地替换。这个识别一旦落空——框架升级换了类名、或列表结构变了——安全检查会**凭空消失**，
 * 而端到端用例只会在恰好构造出禁用账号时才红。因此认不出目标时必须直接拒绝启动，
 * 本类守的就是这条。
 */
class AccountStatusRefreshTokenAuthenticationProviderTest {

    private final OAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();

    private final UserDetailsService userDetailsService = (username) -> {
        throw new UsernameNotFoundException(username);
    };

    private final UserTokenLock userTokenLock = mock(UserTokenLock.class);

    private final PlatformTransactionManager transactionManager = mock(PlatformTransactionManager.class);

    @Test
    void wrapsFrameworkRefreshTokenProviderInPlace() {
        AuthenticationProvider unrelatedProvider = unrelatedProvider();
        List<AuthenticationProvider> providers = new ArrayList<>(
                List.of(unrelatedProvider, frameworkRefreshTokenProvider()));

        AccountStatusRefreshTokenAuthenticationProvider.guardRefreshTokenProvider(
                providers, this.authorizationService, this.userDetailsService,
                this.userTokenLock, this.transactionManager);

        assertThat(providers).hasSize(2);
        // 其余 provider 必须原封不动：装配逻辑越界会把授权码等授权类型一并改掉
        assertThat(providers.get(0)).isSameAs(unrelatedProvider);
        assertThat(providers.get(1)).isInstanceOf(AccountStatusRefreshTokenAuthenticationProvider.class);
    }

    @Test
    void refusesToStartWhenFrameworkRefreshTokenProviderIsAbsent() {
        List<AuthenticationProvider> providers = new ArrayList<>(List.of(unrelatedProvider()));

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> AccountStatusRefreshTokenAuthenticationProvider.guardRefreshTokenProvider(
                        providers, this.authorizationService, this.userDetailsService,
                        this.userTokenLock, this.transactionManager));
    }

    private OAuth2RefreshTokenAuthenticationProvider frameworkRefreshTokenProvider() {
        return new OAuth2RefreshTokenAuthenticationProvider(this.authorizationService, (context) -> null);
    }

    private static AuthenticationProvider unrelatedProvider() {
        return new AuthenticationProvider() {

            @Override
            public Authentication authenticate(Authentication authentication) {
                return null;
            }

            @Override
            public boolean supports(Class<?> authentication) {
                return false;
            }
        };
    }
}
