package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.user.AppUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = {
        "BOOTSTRAP_ADMIN_EMAILS=BOOTSTRAP-ADMIN@EXAMPLE.COM,missing-admin@example.com"
})
@Import(PostgresTestConfig.class)
class BootstrapAdminRunnerTest {

    private static final String PASSWORD = "a valid password";

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    @Qualifier("bootstrapPlatformAdministrators")
    private ApplicationRunner bootstrapRunner;

    @Test
    void promotesOnlyExistingConfiguredUsersAndIsIdempotent() throws Exception {
        AppUser configured = registrationService.register(
                "bootstrap-admin@example.com",
                PASSWORD);
        AppUser ordinary = registrationService.register(
                "ordinary-bootstrap@example.com",
                PASSWORD);

        bootstrapRunner.run(null);
        bootstrapRunner.run(null);

        assertThat(isPlatformAdmin(configured)).isTrue();
        assertThat(isPlatformAdmin(ordinary)).isFalse();
        assertThat(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM app_user WHERE email = 'missing-admin@example.com'",
                Integer.class))
                .isZero();
    }

    private boolean isPlatformAdmin(AppUser user) {
        return Boolean.TRUE.equals(jdbcTemplate.queryForObject(
                "SELECT is_platform_admin FROM app_user WHERE id = ?",
                Boolean.class,
                user.getId()));
    }
}
