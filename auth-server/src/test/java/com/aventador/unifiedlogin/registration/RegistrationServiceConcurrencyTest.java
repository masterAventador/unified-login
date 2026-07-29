package com.aventador.unifiedlogin.registration;

import com.aventador.unifiedlogin.user.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RegistrationServiceConcurrencyTest {

    @Test
    void translatesUniqueIndexViolationIntoEmailAlreadyRegistered() {
        UserService userService = mock(UserService.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        when(userService.emailExists(any())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("hash-value");
        when(userService.createUser(any(), anyString()))
                .thenThrow(new DataIntegrityViolationException("ux_app_user_email"));

        RegistrationService service = new RegistrationService(userService, passwordEncoder);

        assertThatThrownBy(() -> service.register("race@example.com", "a valid password"))
                .isInstanceOf(EmailAlreadyRegisteredException.class);
    }
}
