package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.account.UserTokenLock;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.transaction.PlatformTransactionManager;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

class UserLockedAuthorizationCodeAuthenticationProviderTest {

    private final OAuth2AuthorizationService authorizationService =
            new InMemoryOAuth2AuthorizationService();

    private final UserTokenLock userTokenLock = mock(UserTokenLock.class);

    private final PlatformTransactionManager transactionManager =
            mock(PlatformTransactionManager.class);

    @Test
    void wrapsFrameworkAuthorizationCodeProviderInPlace() {
        AuthenticationProvider unrelatedProvider = unrelatedProvider();
        List<AuthenticationProvider> providers = new ArrayList<>(
                List.of(unrelatedProvider, frameworkAuthorizationCodeProvider()));

        UserLockedAuthorizationCodeAuthenticationProvider.guardAuthorizationCodeProvider(
                providers, this.authorizationService, this.userTokenLock, this.transactionManager);

        assertThat(providers).hasSize(2);
        assertThat(providers.get(0)).isSameAs(unrelatedProvider);
        assertThat(providers.get(1))
                .isInstanceOf(UserLockedAuthorizationCodeAuthenticationProvider.class);
    }

    @Test
    void refusesToStartWhenFrameworkAuthorizationCodeProviderIsAbsent() {
        List<AuthenticationProvider> providers = new ArrayList<>(List.of(unrelatedProvider()));

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() ->
                        UserLockedAuthorizationCodeAuthenticationProvider.guardAuthorizationCodeProvider(
                                providers, this.authorizationService,
                                this.userTokenLock, this.transactionManager));
    }

    private OAuth2AuthorizationCodeAuthenticationProvider frameworkAuthorizationCodeProvider() {
        return new OAuth2AuthorizationCodeAuthenticationProvider(
                this.authorizationService, (context) -> null);
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
