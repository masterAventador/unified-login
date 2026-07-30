package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.user.EmailAddress;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

@Configuration
public class BootstrapAdminRunner {

    /**
     * 只提升启动时已经存在的账号，不创建用户。
     *
     * <p>配置移除也不会自动撤销管理员身份；这与客户端配置的增量同步语义一致，
     * 避免一次错误部署把现有管理员全部锁在后台之外。
     */
    @Bean
    public ApplicationRunner bootstrapPlatformAdministrators(
            JdbcTemplate jdbcTemplate,
            UnifiedLoginProperties properties) {
        return (args) -> {
            for (String rawEmail : properties.bootstrapAdminEmailsOrEmpty()) {
                if (rawEmail == null || rawEmail.isBlank()) {
                    continue;
                }
                String email = new EmailAddress(rawEmail).value();
                jdbcTemplate.update("""
                        UPDATE app_user
                        SET is_platform_admin = true,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE email = ?
                          AND is_platform_admin = false
                        """, email);
            }
        };
    }
}
