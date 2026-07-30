package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.account.PasswordChangeRateLimitFilter;
import com.aventador.unifiedlogin.security.LoginAttemptService;
import com.aventador.unifiedlogin.security.LoginPaths;
import com.aventador.unifiedlogin.security.LoginRateLimitFilter;
import com.aventador.unifiedlogin.security.LoginRateLimitProperties;
import com.github.benmanes.caffeine.cache.Ticker;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(LoginRateLimitProperties.class)
public class SecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          LoginAttemptService loginAttemptService) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        // /error 必须放行：Spring Security 7 默认拦截 ERROR dispatch，
                        // 不放行时未捕获异常的错误页转发会被再拦一次，500 都呈现不出来
                        .requestMatchers("/register", LoginPaths.LOGIN, "/error").permitAll()
                        .anyRequest().authenticated())
                .formLogin((formLogin) -> formLogin
                        // 必须指定自定义登录页：默认配置会启用登录页生成过滤器，遮蔽 Thymeleaf 模板
                        .loginPage(LoginPaths.LOGIN))
                // 必须排在认证过滤器之前：被锁的提交要在触发密码校验之前就被挡掉
                .addFilterBefore(new LoginRateLimitFilter(loginAttemptService),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new PasswordChangeRateLimitFilter(loginAttemptService),
                        AuthorizationFilter.class);

        return http.build();
    }

    /**
     * 限流计数的时间源。生产用系统时钟；测试注入可推进的假时钟，
     * 这样验证「锁定十五分钟后自动解锁」不必真的等十五分钟。
     */
    @Bean
    public Ticker loginAttemptTicker() {
        return Ticker.systemTicker();
    }
}
