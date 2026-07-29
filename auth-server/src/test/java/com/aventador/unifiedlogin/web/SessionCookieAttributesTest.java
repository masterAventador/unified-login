package com.aventador.unifiedlogin.web;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 守住认证中心主会话 Cookie 的四项属性。
 *
 * <p>这四项此前没有任何测试守护：把 {@code http-only}、{@code secure} 同时改成 false、
 * {@code same-site} 改成 none 之后跑全量，142 个用例照样全绿。它们各自失守的后果都是直接的：
 * {@code secure=false} 悄悄取消 HTTPS 绑定；{@code http-only=false} 把主会话暴露给该域上任意
 * XSS；{@code same-site=none} 配 {@code secure=false} 会让浏览器直接丢弃 Cookie、全站登录挂掉；
 * 缺 {@code Max-Age} 则退化成浏览器会话 Cookie——用户一关浏览器，规格书 §7.2 的跨产品免登与
 * §7.4 的桌面端会话复用当场归零。
 *
 * <p>必须起真实服务器：MockMvc 不经过 Tomcat 的 Cookie 序列化，拿不到真正下发的
 * {@code Set-Cookie} 头，断言只能落在配置对象的读数上——那等于用配置证明配置。这里用 JDK 自带
 * 的 HTTP 客户端直接读原始响应头，并关掉自动重定向，好让登录成功与否本身也能被断言。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(PostgresTestConfig.class)
class SessionCookieAttributesTest {

    private static final String EMAIL = "session-cookie@example.com";

    private static final String PASSWORD = "a valid password";

    /** 与 application.yml 的 server.servlet.session.cookie.name 一致。 */
    private static final String COOKIE_NAME = "AUTH_SESSION";

    /** 规格书 §6.3：认证中心会话 Cookie 有效期 14 天。 */
    private static final Duration EXPECTED_MAX_AGE = Duration.ofDays(14);

    private static final Pattern CSRF_INPUT = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"");

    private final HttpClient httpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    @LocalServerPort
    private int port;

    @Autowired
    private RegistrationService registrationService;

    @Test
    void loginIssuesSessionCookieWithAllProtectiveAttributes() throws Exception {
        registrationService.register(EMAIL, PASSWORD);

        HttpResponse<String> loginPage = send(HttpRequest.newBuilder(uri("/login")).GET());
        assertThat(loginPage.statusCode()).isEqualTo(200);
        String preLoginSessionId = sessionIdOf(sessionCookieHeader(loginPage));

        HttpResponse<String> loginResponse = submitLogin(csrfTokenOf(loginPage.body()), preLoginSessionId);

        // 先确认真的登录成功：凭据被拒同样是 302，但去向是 /login?error，
        // 那种情况下断言 Cookie 属性，验的就不是「登录后的主会话」了
        assertThat(loginResponse.statusCode()).isEqualTo(302);
        assertThat(loginResponse.headers().firstValue("Location"))
                .hasValueSatisfying((location) -> assertThat(URI.create(location).getPath()).isEqualTo("/"));

        String setCookie = sessionCookieHeader(loginResponse);
        // 会话固定防护会换一个新会话，这一条同时保证下面断言的是登录后新下发的那个 Cookie
        assertThat(sessionIdOf(setCookie)).isNotEqualTo(preLoginSessionId);

        assertThat(setCookie)
                .as("登录后下发的会话 Cookie")
                .contains("; HttpOnly")
                .contains("; Secure")
                .contains("; SameSite=Lax")
                .contains("; Max-Age=" + EXPECTED_MAX_AGE.getSeconds());
    }

    private HttpResponse<String> submitLogin(String csrfToken, String sessionId) throws Exception {
        String body = formBody(Map.of("username", EMAIL, "password", PASSWORD, "_csrf", csrfToken));

        return send(HttpRequest.newBuilder(uri("/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", COOKIE_NAME + "=" + sessionId)
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)));
    }

    private HttpResponse<String> send(HttpRequest.Builder request) throws IOException, InterruptedException {
        return this.httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + this.port + path);
    }

    private static String formBody(Map<String, String> fields) {
        return fields.entrySet().stream()
                .map((field) -> encode(field.getKey()) + "=" + encode(field.getValue()))
                .collect(Collectors.joining("&"));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String sessionCookieHeader(HttpResponse<String> response) {
        List<String> setCookies = response.headers().allValues("Set-Cookie");
        return setCookies.stream()
                .filter((cookie) -> cookie.startsWith(COOKIE_NAME + "="))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "响应里没有 " + COOKIE_NAME + " 的 Set-Cookie 头：" + setCookies));
    }

    private static String sessionIdOf(String setCookieHeader) {
        return setCookieHeader.substring((COOKIE_NAME + "=").length(), setCookieHeader.indexOf(';'));
    }

    private static String csrfTokenOf(String loginPageHtml) {
        Matcher matcher = CSRF_INPUT.matcher(loginPageHtml);
        assertThat(matcher.find()).as("登录页应渲染出 CSRF 隐藏字段").isTrue();
        return matcher.group(1);
    }
}
