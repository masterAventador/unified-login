package com.aventador.unifiedlogin.support;

import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
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
        var builder = UriComponentsBuilder.fromPath("/oauth2/authorize");
        for (var entry : params.entrySet()) {
            builder.queryParam(entry.getKey(), entry.getValue());
        }
        return builder.build().toString();
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

    /** 以已登录用户身份走一次授权端点，返回回调地址中的一次性授权码。 */
    public static String authorizeAndExtractCode(MockMvc mockMvc, String userEmail) throws Exception {
        MvcResult result = mockMvc.perform(get(authorizeUri(validAuthorizeParams()))
                        .with(user(userEmail)))
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

    /** 从令牌响应中取出某个字符串字段的值。 */
    public static String jsonField(String json, String field) {
        String marker = "\"" + field + "\":\"";
        int start = json.indexOf(marker);
        assertThat(start).as("响应中应包含字段 %s", field).isGreaterThanOrEqualTo(0);
        start += marker.length();
        int end = json.indexOf('"', start);
        return json.substring(start, end);
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
