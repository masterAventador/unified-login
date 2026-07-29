package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import static com.aventador.unifiedlogin.support.OAuth2TestFlows.CLIENT_ID;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.CODE_VERIFIER;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.REDIRECT_URI;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.authorizeAndExtractCode;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 令牌端点的跨域放行。
 *
 * <p>浏览器里的接入方是从自己的源（如 http://localhost:5173）用 fetch 调
 * http://localhost:9000/oauth2/token 换令牌的，属于跨源请求。响应缺少
 * {@code Access-Control-Allow-Origin} 时，服务端照样 200、令牌照样签发，
 * 但浏览器会把响应整个丢掉，页面只拿到一个 "Failed to fetch"——
 * 服务端日志里看不出任何异常。因此这里断言的是「浏览器是否会把响应交给页面」，
 * 而不是「服务端有没有返回 200」。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class TokenEndpointCorsTest {

    private static final String USER_EMAIL = "cors@example.com";

    private static final String PASSWORD = "a valid password";

    /** demo-web-a 回调地址所在的源，即注册在案的接入方来源。 */
    private static final String REGISTERED_ORIGIN = "http://localhost:5173";

    private static final String UNREGISTERED_ORIGIN = "http://attacker.example.com";

    private static final String TOKEN_ENDPOINT = "/oauth2/token";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    private MockHttpSession session;

    @BeforeEach
    void createUserAndLogin() throws Exception {
        if (!registrationService.isEmailTaken(USER_EMAIL)) {
            registrationService.register(USER_EMAIL, PASSWORD);
        }
        session = OAuth2TestFlows.login(mockMvc, USER_EMAIL, PASSWORD);
    }

    @Test
    void registeredOriginCanReadTokenResponse() throws Exception {
        String code = authorizeAndExtractCode(mockMvc, session);

        mockMvc.perform(post(TOKEN_ENDPOINT)
                        .header(HttpHeaders.ORIGIN, REGISTERED_ORIGIN)
                        .param("grant_type", "authorization_code")
                        .param("client_id", CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(header().string("Access-Control-Allow-Origin", REGISTERED_ORIGIN));
    }

    /**
     * 换令牌前浏览器可能先发预检（例如接入方带上了自定义请求头）。预检若没被放行，
     * 真正的 POST 根本不会发出，表现同样是页面侧一句 "Failed to fetch"。
     */
    @Test
    void registeredOriginPassesPreflight() throws Exception {
        mockMvc.perform(options(TOKEN_ENDPOINT)
                        .header(HttpHeaders.ORIGIN, REGISTERED_ORIGIN)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", REGISTERED_ORIGIN))
                .andExpect(header().string("Access-Control-Allow-Methods",
                        org.hamcrest.Matchers.containsString("POST")));
    }

    /** 没登记过的源必须拿不到放行头，否则任意站点都能在受害者浏览器里替他换令牌。 */
    @Test
    void unregisteredOriginIsNotAllowedToReadTokenResponse() throws Exception {
        String code = authorizeAndExtractCode(mockMvc, session);

        mockMvc.perform(post(TOKEN_ENDPOINT)
                        .header(HttpHeaders.ORIGIN, UNREGISTERED_ORIGIN)
                        .param("grant_type", "authorization_code")
                        .param("client_id", CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }
}
