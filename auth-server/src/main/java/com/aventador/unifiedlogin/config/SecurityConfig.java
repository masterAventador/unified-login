package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.account.PasswordChangeRateLimitFilter;
import com.aventador.unifiedlogin.admin.PlatformAdminGuard;
import com.aventador.unifiedlogin.security.LoginAttemptService;
import com.aventador.unifiedlogin.security.LoginPaths;
import com.aventador.unifiedlogin.security.LoginRateLimitFilter;
import com.aventador.unifiedlogin.security.LoginRateLimitProperties;
import com.github.benmanes.caffeine.cache.Ticker;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(LoginRateLimitProperties.class)
public class SecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          LoginAttemptService loginAttemptService,
                                                          PlatformAdminGuard platformAdminGuard) throws Exception {
        RequestMatcher adminEndpoints = PathPatternRequestMatcher.pathPattern("/admin/**");
        http
                .authorizeHttpRequests((authorize) -> authorize
                        // /error 必须放行：Spring Security 7 默认拦截 ERROR dispatch，
                        // 不放行时未捕获异常的错误页转发会被再拦一次，500 都呈现不出来
                        .requestMatchers("/register", LoginPaths.LOGIN, "/error").permitAll()
                        .requestMatchers(adminEndpoints).access(platformAdminGuard)
                        .anyRequest().authenticated())
                .formLogin((formLogin) -> formLogin
                        // 必须指定自定义登录页：默认配置会启用登录页生成过滤器，遮蔽 Thymeleaf 模板
                        .loginPage(LoginPaths.LOGIN))
                // 管理 SPA 用阶段二 SDK 拿到的 access token 调管理 API；默认链若不启用
                // resource server，只会把合法 Bearer token 当匿名请求重定向到登录页。
                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()))
                .exceptionHandling((exceptions) -> exceptions
                        // resource server 默认会把整条链的匿名响应都改成 401。管理 API 需要
                        // 这个语义，但认证中心页面必须继续跳登录页，故按路径明确分流。
                        .defaultAuthenticationEntryPointFor(
                                new BearerTokenAuthenticationEntryPoint(), adminEndpoints)
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint(LoginPaths.LOGIN),
                                new NegatedRequestMatcher(adminEndpoints)))
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
