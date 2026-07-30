package com.aventador.unifiedlogin.admin;

import com.aventador.unifiedlogin.account.TokenRevocationService;
import com.aventador.unifiedlogin.account.UserTokenLock;
import com.aventador.unifiedlogin.user.AppUserRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AdminUserServiceTest {

    @Test
    void usesUniqueStableOrderForPagination() {
        AppUserRepository userRepository = mock(AppUserRepository.class);
        when(userRepository.search(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.isNull(),
                org.mockito.ArgumentMatchers.any(Pageable.class)))
                .thenReturn(Page.empty());
        AdminUserService service = new AdminUserService(
                userRepository,
                mock(PasswordEncoder.class),
                mock(TokenRevocationService.class),
                mock(UserTokenLock.class));

        service.list("", null, 0, 20);

        ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
        verify(userRepository).search(
                org.mockito.ArgumentMatchers.eq(""),
                org.mockito.ArgumentMatchers.isNull(),
                pageable.capture());
        assertThat(pageable.getValue().getSort().toList())
                .extracting(Sort.Order::getProperty, Sort.Order::getDirection)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple("createdAt", Sort.Direction.DESC),
                        org.assertj.core.groups.Tuple.tuple("id", Sort.Direction.ASC));
    }
}
