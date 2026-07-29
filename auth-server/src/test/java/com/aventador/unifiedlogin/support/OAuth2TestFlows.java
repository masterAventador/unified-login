package com.aventador.unifiedlogin.support;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public final class OAuth2TestFlows {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

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
        return validAuthorizeParams(CLIENT_ID);
    }

    /** 同上，指定客户端。用于需要第二个客户端参与的场景。 */
    public static Map<String, String> validAuthorizeParams(String clientId) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", clientId);
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
        return authorizeAndExtractCode(mockMvc, session, CLIENT_ID);
    }

    /** 同上，指定客户端。 */
    public static String authorizeAndExtractCode(MockMvc mockMvc, MockHttpSession session, String clientId)
            throws Exception {
        MvcResult result = mockMvc.perform(get(authorizeUri(validAuthorizeParams(clientId)))
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String location = result.getResponse().getRedirectedUrl();
        assertThat(location).startsWith(REDIRECT_URI);

        return queryParam(location, "code");
    }

    /** 用授权码换取令牌，返回响应 JSON 原文。仅用于预期成功的场景。 */
    public static String exchangeCode(MockMvc mockMvc, String code) throws Exception {
        return exchangeCode(mockMvc, code, CLIENT_ID);
    }

    /** 同上，指定客户端。 */
    public static String exchangeCode(MockMvc mockMvc, String code, String clientId) throws Exception {
        return mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", clientId)
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
    }

    /**
     * 从令牌响应中取出某个字段的值。用 Jackson 而非字符串查找：
     * 后者只能取带引号的字符串字段，遇到数字/布尔字段会误报「字段不存在」，
     * 把后续任务的排查方向带偏。
     */
    // Jackson 3 的异常全部是非受检的，这里不需要（也不应该）包 try/catch：
    // JSON 解析不了时让原始异常直接抛出，比包装成 AssertionError 更好排查
    public static String jsonField(String json, String field) {
        JsonNode node = OBJECT_MAPPER.readTree(json).path(field);
        assertThat(node.isMissingNode()).as("响应中应包含字段 %s", field).isFalse();
        return node.asText();
    }

    /** 用 refresh token 换一组新令牌，返回响应 JSON 原文。 */
    public static String refreshTokens(MockMvc mockMvc, String refreshToken) throws Exception {
        return refreshTokens(mockMvc, refreshToken, CLIENT_ID);
    }

    /** 同上，指定客户端。 */
    public static String refreshTokens(MockMvc mockMvc, String refreshToken, String clientId) throws Exception {
        return mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", clientId)
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
    }

    /**
     * 解析回调地址上的查询参数。
     *
     * <p>授权端点的参数错误同样是经由回调地址回传的（RFC 6749 §4.1.2.1），断言这类
     * 响应时既要看回传了哪些参数，也要看**没有**回传哪些（比如授权码），因此需要拿到全集。
     */
    public static Map<String, String> queryParams(String url) {
        String query = URI.create(url).getQuery();
        assertThat(query).as("回调地址应带查询参数：%s", url).isNotNull();

        return Arrays.stream(query.split("&"))
                .map((pair) -> pair.split("=", 2))
                .filter((parts) -> parts.length == 2)
                // 同名参数取第一个，与 queryParam 原有语义一致
                .collect(Collectors.toMap((parts) -> parts[0], (parts) -> parts[1],
                        (first, duplicate) -> first, LinkedHashMap::new));
    }

    private static String queryParam(String url, String name) {
        String value = queryParams(url).get(name);
        assertThat(value).as("回调地址中没有 %s 参数：%s", name, url).isNotNull();
        return value;
    }
}
