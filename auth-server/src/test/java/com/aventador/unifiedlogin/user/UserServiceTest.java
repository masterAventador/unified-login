package com.aventador.unifiedlogin.user;

import com.aventador.unifiedlogin.PostgresTestConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Import(PostgresTestConfig.class)
class UserServiceTest {

    @Autowired
    private UserService userService;

    @Autowired
    private AppUserRepository repository;

    @Test
    void createsUserWithActiveStatusAndGeneratedId() {
        AppUser user = userService.createUser(new EmailAddress("create@example.com"), "hash-value");

        assertThat(user.getId()).isNotNull();
        assertThat(user.getEmail()).isEqualTo("create@example.com");
        assertThat(user.getPasswordHash()).isEqualTo("hash-value");
        assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
        assertThat(user.isPlatformAdmin()).isFalse();
        assertThat(user.getPasswordChangedAt()).isNotNull();
    }

    @Test
    void persistsEmailInLowerCase() {
        userService.createUser(new EmailAddress("MiXeD@Example.COM"), "hash-value");

        assertThat(repository.findByEmail("mixed@example.com")).isPresent();
    }

    @Test
    void findsUserRegardlessOfInputCase() {
        userService.createUser(new EmailAddress("lookup@example.com"), "hash-value");

        Optional<AppUser> found = userService.findByEmail(new EmailAddress("LookUp@Example.com"));

        assertThat(found).isPresent();
    }

    @Test
    void reportsExistingEmail() {
        userService.createUser(new EmailAddress("exists@example.com"), "hash-value");

        assertThat(userService.emailExists(new EmailAddress("exists@example.com"))).isTrue();
        assertThat(userService.emailExists(new EmailAddress("absent@example.com"))).isFalse();
    }

    @Test
    void returnsEmptyForUnknownEmail() {
        assertThat(userService.findByEmail(new EmailAddress("unknown@example.com"))).isEmpty();
    }
}
