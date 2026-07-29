package com.aventador.unifiedlogin.support;

import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public final class OAuth2TestFlows {

    public static final String CLIENT_ID = "demo-web-a";
    public static final String REDIRECT_URI = "http://localhost:5173/callback";
    public static final String CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    public static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private OAuth2TestFlows() {
    }

    /**
     * 构造授权端点 URI。**参数必须放在 query string 里**：框架用
     * request.getQueryString() 过滤授权参数，而 MockMvc 的 .param() 不填充 queryString，
     * 用 .param() 会让参数被整批丢弃、端点报 invalid_request。
     */
    public static String authorizeUri(Map<String, String> params) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromPath("/oauth2/authorize");
        params.forEach(builder::queryParam);
        // 必须 encode()：Task 10 会构造含特殊字符的非法参数来测边界，
        // 不编码时这些字符会破坏查询串结构，失败现象与测试意图无关、极难排查
        return builder.build().encode().toString();
    }

    /** 标准的合法授权请求参数（可按需覆盖或删改某项来构造异常场景）。 */
    public static Map<String, String> validAuthorizeParams() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("scope", "openid");
        params.put("code_challenge", CODE_CHALLENGE);
        params.put("code_challenge_method", "S256");
        return params;
    }

    /**
     * 走真实表单登录并返回会话。
     *
     * **不能用 `.with(user(...))` 替代**：那样造出的主体缺少 Spring Security 7 的
     * FactorGrantedAuthority，而框架签发 token 时要从它推导认证时间，
     * 会抛 "authenticationTime cannot be null"。必须走真实登录链路。
     */
    public static MockHttpSession login(MockMvc mockMvc, String email, String rawPassword) throws Exception {
        MvcResult result = mockMvc.perform(formLogin("/login").user(email).password(rawPassword))
                .andExpect(authenticated())
                .andReturn();

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        assertThat(session).as("登录后应存在会话").isNotNull();
        return session;
    }

    /** 以已登录会话走一次授权端点，返回回调地址中的一次性授权码。 */
    public static String authorizeAndExtractCode(MockMvc mockMvc, MockHttpSession session) throws Exception {
        MvcResult result = mockMvc.perform(get(authorizeUri(validAuthorizeParams()))
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String location = result.getResponse().getRedirectedUrl();
        assertThat(location).startsWith(REDIRECT_URI);

        return queryParam(location, "code");
    }

    /** 用授权码换取令牌，返回响应 JSON 原文。仅用于预期成功的场景。 */
    public static String exchangeCode(MockMvc mockMvc, String code) throws Exception {
        return mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
    }

    /**
     * 从令牌响应中取出某个字段的值。支持字符串/数字/布尔字段。
     */
    public static String jsonField(String json, String field) {
        String pattern = "\"" + field + "\":";
        int idx = json.indexOf(pattern);
        assertThat(idx).as("响应中应包含字段 %s", field).isGreaterThanOrEqualTo(0);

        int valueStart = idx + pattern.length();
        // 跳过空格
        while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
            valueStart++;
        }

        char firstChar = json.charAt(valueStart);
        if (firstChar == '"') {
            // 字符串值：找到闭合引号
            int endIndex = valueStart + 1;
            while (endIndex < json.length()) {
                if (json.charAt(endIndex) == '"' && (endIndex == 0 || json.charAt(endIndex - 1) != '\\')) {
                    return json.substring(valueStart + 1, endIndex);
                }
                endIndex++;
            }
            throw new AssertionError("字段 " + field + " 的字符串值没有闭合引号");
        } else {
            // 非字符串值：提取直到逗号或右花括号
            int endIndex = valueStart;
            while (endIndex < json.length() && json.charAt(endIndex) != ',' && json.charAt(endIndex) != '}') {
                endIndex++;
            }
            return json.substring(valueStart, endIndex).trim();
        }
    }

    /** 用 refresh token 换一组新令牌，返回响应 JSON 原文。 */
    public static String refreshTokens(MockMvc mockMvc, String refreshToken) throws Exception {
        return mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", CLIENT_ID)
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
    }

    private static String queryParam(String url, String name) {
        String query = URI.create(url).getQuery();
        assertThat(query).as("回调地址应带查询参数：%s", url).isNotNull();

        return Arrays.stream(query.split("&"))
                .map((pair) -> pair.split("=", 2))
                .filter((parts) -> parts.length == 2 && parts[0].equals(name))
                .map((parts) -> parts[1])
                .findFirst()
                .orElseThrow(() -> new AssertionError("回调地址中没有 " + name + " 参数：" + url));
    }
}
