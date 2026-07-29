package com.aventador.unifiedlogin.security;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@Import(PostgresTestConfig.class)
class AppUserDetailsServiceTest {

    @Autowired
    private AppUserDetailsService userDetailsService;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void loadsUserByEmail() {
        registrationService.register("details@example.com", "a valid password");

        UserDetails details = userDetailsService.loadUserByUsername("details@example.com");

        assertThat(details.getUsername()).isEqualTo("details@example.com");
        assertThat(details.isEnabled()).isTrue();
    }

    @Test
    void loadsUserIgnoringInputCase() {
        registrationService.register("case-details@example.com", "a valid password");

        UserDetails details = userDetailsService.loadUserByUsername("Case-Details@Example.COM");

        assertThat(details.getUsername()).isEqualTo("case-details@example.com");
    }

    @Test
    void disabledUserIsMappedAsDisabled() {
        registrationService.register("disabled-details@example.com", "a valid password");
        // 领域模型尚无禁用入口（管理后台在后续阶段），测试用 SQL 直接翻转状态，不新增生产代码
        jdbcTemplate.update("UPDATE app_user SET status = 'DISABLED' WHERE email = ?",
                "disabled-details@example.com");

        UserDetails details = userDetailsService.loadUserByUsername("disabled-details@example.com");

        assertThat(details.isEnabled()).isFalse();
    }

    @Test
    void throwsForUnknownEmail() {
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("nobody@example.com"))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void throwsForMalformedEmailInsteadOfLeakingParseError() {
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("not-an-email"))
                .isInstanceOf(UsernameNotFoundException.class);
    }
}
