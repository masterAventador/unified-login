package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.admin.AdminClient;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * 浏览器客户端调用令牌端点与管理 API 时的跨域放行。
 *
 * <p>浏览器里的接入方部署在自己的源上（demo-web-a 是 http://localhost:5173），换令牌时
 * 要跨源 POST 到认证中心。缺少 {@code Access-Control-Allow-Origin} 时服务端一切正常——
 * 令牌照签、状态码 200、日志无异常——但浏览器会把响应整个丢弃，页面只看到
 * "Failed to fetch"。因此这是接入方能否登录成功的必要条件，不是可选的加固项。
 *
 * <p><b>允许的源来自已注册客户端的回调地址</b>，不另立一份名单：回调白名单本就是
 * 「哪些源是我们承认的接入方」的唯一事实来源，另开一份迟早会与它不同步。
 */
@Configuration
public class TokenEndpointCorsConfig {

    private static final Duration PREFLIGHT_CACHE_TTL = Duration.ofHours(1);

    /**
     * 注册成全局 Servlet 过滤器而不是用 {@code http.cors(...)}。
     *
     * <p>原因是预检：{@code OAuth2AuthorizationServerConfigurer} 的端点匹配器
     * 对令牌端点只匹配 POST，浏览器发来的 {@code OPTIONS /oauth2/token} 落不进
     * 授权服务器那条过滤器链，而是掉进默认链被判为未认证、302 跳登录页——
     * 于是真正的 POST 根本不会发出。放在所有安全链之前统一处理才能同时覆盖
     * 预检与实际请求。
     */
    @Bean
    public FilterRegistrationBean<CorsFilter> tokenEndpointCorsFilter(
            UnifiedLoginProperties properties,
            AuthorizationServerSettings authorizationServerSettings) {
        List<String> allowedOrigins = registeredClientOrigins(properties);

        CorsConfiguration tokenEndpoint = new CorsConfiguration();
        tokenEndpoint.setAllowedOrigins(allowedOrigins);
        tokenEndpoint.setAllowedMethods(List.of(HttpMethod.POST.name()));
        // 令牌端点只吃表单参数，放行 Content-Type 足够；多放行一个请求头就多一分被利用的面
        tokenEndpoint.setAllowedHeaders(List.of(HttpHeaders.CONTENT_TYPE));
        tokenEndpoint.setMaxAge(PREFLIGHT_CACHE_TTL);

        CorsConfiguration adminApi = new CorsConfiguration();
        // 管理 API 只供管理后台调用。普通产品即使也是已登记客户端，也不应获得浏览器
        // 跨域读取管理响应的能力；真正的权限边界仍由 PlatformAdminGuard 的 audience 校验守住。
        adminApi.setAllowedOrigins(registeredClientOrigins(properties, AdminClient.CLIENT_ID));
        adminApi.setAllowedMethods(List.of(HttpMethod.GET.name(), HttpMethod.POST.name()));
        adminApi.setAllowedHeaders(List.of(HttpHeaders.AUTHORIZATION, HttpHeaders.CONTENT_TYPE));
        adminApi.setMaxAge(PREFLIGHT_CACHE_TTL);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(authorizationServerSettings.getTokenEndpoint(), tokenEndpoint);
        source.registerCorsConfiguration("/admin/**", adminApi);

        FilterRegistrationBean<CorsFilter> registration = new FilterRegistrationBean<>(new CorsFilter(source));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }

    static List<String> registeredClientOrigins(UnifiedLoginProperties properties) {
        return registeredClientOrigins(properties, null);
    }

    private static List<String> registeredClientOrigins(
            UnifiedLoginProperties properties,
            String requiredClientId) {
        return properties.clientsOrEmpty().stream()
                .filter((client) -> requiredClientId == null
                        || requiredClientId.equals(client.clientId()))
                .map(UnifiedLoginProperties.ClientConfig::redirectUris)
                .filter(Objects::nonNull)
                .flatMap(List::stream)
                .map(TokenEndpointCorsConfig::originOf)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }

    /**
     * 取浏览器回调地址的源（协议 + 主机 + 端口），丢掉路径。
     *
     * <p>原生客户端的自定义 scheme 与无 host 地址不受浏览器同源策略约束，也不是合法的
     * CORS Origin。把它们灌进 allowedOrigins 会在启动期或首次请求时触发配置异常。
     */
    private static String originOf(String redirectUri) {
        UriComponents uri = UriComponentsBuilder.fromUriString(redirectUri).build();
        String scheme = uri.getScheme();
        if (scheme == null
                || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))
                || !org.springframework.util.StringUtils.hasText(uri.getHost())) {
            return null;
        }
        return UriComponentsBuilder.newInstance()
                .scheme(scheme.toLowerCase(java.util.Locale.ROOT))
                .host(uri.getHost())
                .port(uri.getPort())
                .build()
                .toUriString();
    }
}
