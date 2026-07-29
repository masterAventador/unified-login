package com.aventador.unifiedlogin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        // /error 必须放行：Spring Security 7 默认拦截 ERROR dispatch，
                        // 不放行时未捕获异常的错误页转发会被再拦一次，500 都呈现不出来
                        .requestMatchers("/register", "/login", "/error").permitAll()
                        .anyRequest().authenticated())
                .formLogin((formLogin) -> formLogin
                        // 必须指定自定义登录页：默认配置会启用登录页生成过滤器，遮蔽 Thymeleaf 模板
                        .loginPage("/login"));

        return http.build();
    }
}
