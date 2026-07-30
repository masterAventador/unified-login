package com.aventador.unifiedlogin.registration;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.password.WeakPasswordException;
import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.InvalidEmailException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@Import(PostgresTestConfig.class)
class RegistrationServiceTest {

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void storesHashedPasswordNotRawPassword() {
        AppUser user = registrationService.register("hashing@example.com", "a valid password");

        assertThat(user.getPasswordHash()).isNotEqualTo("a valid password");
        assertThat(passwordEncoder.matches("a valid password", user.getPasswordHash())).isTrue();
    }

    @Test
    void rejectsDuplicateEmailIgnoringCase() {
        registrationService.register("dup@example.com", "a valid password");

        assertThatThrownBy(() -> registrationService.register("DUP@Example.com", "a valid password"))
                .isInstanceOf(EmailAlreadyRegisteredException.class);
    }

    @Test
    void rejectsInvalidEmail() {
        assertThatThrownBy(() -> registrationService.register("not-an-email", "a valid password"))
                .isInstanceOf(InvalidEmailException.class);
    }

    @Test
    void rejectsWeakPassword() {
        assertThatThrownBy(() -> registrationService.register("weak@example.com", "short"))
                .isInstanceOf(WeakPasswordException.class);
    }

    @Test
    void doesNotCreateUserWhenPasswordRejected() {
        assertThatThrownBy(() -> registrationService.register("rollback@example.com", "short"))
                .isInstanceOf(WeakPasswordException.class);

        assertThat(registrationService.isEmailTaken("rollback@example.com")).isFalse();
    }
}
