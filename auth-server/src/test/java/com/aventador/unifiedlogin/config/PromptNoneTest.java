package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.security.LoginPaths;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.net.URI;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class PromptNoneTest {

    private static final String USER_EMAIL = "prompt-none@example.com";

    private static final String PASSWORD = "a valid password";

    private static final String STATE = "prompt-none-state";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @BeforeEach
    void createUser() {
        if (!registrationService.isEmailTaken(USER_EMAIL)) {
            registrationService.register(USER_EMAIL, PASSWORD);
        }
    }

    @Test
    void authenticatedPromptNoneRequestReturnsAuthorizationCode() throws Exception {
        MockHttpSession session = OAuth2TestFlows.login(mockMvc, USER_EMAIL, PASSWORD);

        MvcResult result = mockMvc.perform(get(promptNoneAuthorizeUri()).session(session))
                .andExpect(status().isFound())
                .andReturn();

        String location = result.getResponse().getRedirectedUrl();
        assertThat(location).startsWith(OAuth2TestFlows.REDIRECT_URI);
        assertThat(OAuth2TestFlows.queryParams(location))
                .containsKey("code")
                .containsEntry("state", STATE)
                .doesNotContainKey("error");
    }

    @Test
    void anonymousPromptNoneRequestReturnsLoginRequiredToRegisteredRedirectUri() throws Exception {
        MvcResult result = mockMvc.perform(get(promptNoneAuthorizeUri()))
                .andExpect(status().isFound())
                .andReturn();

        String location = result.getResponse().getRedirectedUrl();
        assertThat(location).startsWith(OAuth2TestFlows.REDIRECT_URI);
        assertThat(OAuth2TestFlows.queryParams(location))
                .containsEntry("error", "login_required")
                .containsEntry("state", STATE)
                .doesNotContainKey("code");
    }

    @Test
    void anonymousPromptNoneRequestStillValidatesPkceBeforeReturningLoginRequired() throws Exception {
        Map<String, String> params = promptNoneAuthorizeParams();
        params.remove("code_challenge");
        params.remove("code_challenge_method");

        MvcResult result = mockMvc.perform(get(OAuth2TestFlows.authorizeUri(params)))
                .andExpect(status().isFound())
                .andReturn();

        String location = result.getResponse().getRedirectedUrl();
        assertThat(location).startsWith(OAuth2TestFlows.REDIRECT_URI);
        assertThat(OAuth2TestFlows.queryParams(location))
                .containsEntry("error", "invalid_request")
                .containsEntry("state", STATE)
                .doesNotContainKeys("code", "login_required");
    }

    @Test
    void anonymousPromptNoneRequestStillValidatesScopeBeforeReturningLoginRequired() throws Exception {
        Map<String, String> params = promptNoneAuthorizeParams();
        params.put("scope", "openid forbidden");

        MvcResult result = mockMvc.perform(get(URI.create(OAuth2TestFlows.authorizeUri(params))))
                .andExpect(status().isFound())
                .andReturn();

        assertThat(OAuth2TestFlows.queryParams(result.getResponse().getRedirectedUrl()))
                .containsEntry("error", "invalid_scope")
                .containsEntry("state", STATE)
                .doesNotContainKeys("code", "login_required");
    }

    @Test
    void anonymousPromptNoneRequestRejectsIllegalPromptCombination() throws Exception {
        Map<String, String> params = promptNoneAuthorizeParams();
        params.put("prompt", "none login");

        MvcResult result = mockMvc.perform(get(URI.create(OAuth2TestFlows.authorizeUri(params))))
                .andExpect(status().isFound())
                .andReturn();

        assertThat(OAuth2TestFlows.queryParams(result.getResponse().getRedirectedUrl()))
                .containsEntry("error", "invalid_request")
                .containsEntry("state", STATE)
                .doesNotContainKeys("code", "login_required");
    }

    @Test
    void anonymousPromptNoneRequestRejectsUnsupportedResponseTypeBeforeLoginHandling() throws Exception {
        Map<String, String> params = promptNoneAuthorizeParams();
        params.put("response_type", "token");

        MvcResult result = mockMvc.perform(get(OAuth2TestFlows.authorizeUri(params)))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl()).isNull();
        assertThat(result.getResponse().getErrorMessage()).contains("unsupported_response_type");
    }

    @Test
    void anonymousInteractiveRequestStillRedirectsToLogin() throws Exception {
        mockMvc.perform(get(OAuth2TestFlows.authorizeUri(OAuth2TestFlows.validAuthorizeParams())))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    void authorizationEndpointCanBeFramedForSilentRenewal() throws Exception {
        mockMvc.perform(get(promptNoneAuthorizeUri()))
                .andExpect(status().isFound())
                .andExpect(header().doesNotExist("X-Frame-Options"));
    }

    @Test
    void loginPageStillDeniesFraming() throws Exception {
        mockMvc.perform(get(LoginPaths.LOGIN))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Frame-Options", "DENY"));
    }

    @Test
    void otherAuthorizationServerEndpointsStillDenyFraming() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Frame-Options", "DENY"));
    }

    @Test
    void promptNoneRequestWithUnregisteredRedirectUriDoesNotRedirect() throws Exception {
        Map<String, String> params = promptNoneAuthorizeParams();
        params.put("redirect_uri", "https://attacker.example.com/steal");

        MvcResult result = mockMvc.perform(get(OAuth2TestFlows.authorizeUri(params)))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl()).isNull();
    }

    @Test
    void promptNoneEntryPointItselfRejectsUnregisteredRedirectUri() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        promptNoneAuthorizeParams().forEach(request::setParameter);
        request.setParameter("redirect_uri", "https://attacker.example.com/steal");
        MockHttpServletResponse response = new MockHttpServletResponse();

        PromptNoneAuthenticationEntryPoint entryPoint = new PromptNoneAuthenticationEntryPoint(
                registeredClientRepository,
                new LoginUrlAuthenticationEntryPoint(LoginPaths.LOGIN));
        entryPoint.commence(request, response, new InsufficientAuthenticationException("test"));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getRedirectedUrl()).isNull();
    }

    @Test
    void promptNoneEntryPointAllowsDynamicLoopbackPort() throws Exception {
        String requestedRedirectUri = "http://127.0.0.1:49321/callback";
        MockHttpServletResponse response = invokeEntryPoint(
                "http://127.0.0.1:8000/callback",
                requestedRedirectUri);

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl())
                .isEqualTo(requestedRedirectUri + "?error=login_required&state=" + STATE);
    }

    @Test
    void promptNoneEntryPointPreservesEncodedRegisteredRedirectUri() throws Exception {
        String redirectUri = "https://client.example/callback?next=%2Fdashboard";
        MockHttpServletResponse response = invokeEntryPoint(redirectUri, redirectUri);

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl())
                .isEqualTo(redirectUri + "&error=login_required&state=" + STATE);
    }

    private static MockHttpServletResponse invokeEntryPoint(String registeredRedirectUri,
                                                            String requestedRedirectUri) throws Exception {
        RegisteredClient client = RegisteredClient.withId("prompt-none-review-client-id")
                .clientId("prompt-none-review-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(registeredRedirectUri)
                .scope(OidcScopes.OPENID)
                .build();
        PromptNoneAuthenticationEntryPoint entryPoint = new PromptNoneAuthenticationEntryPoint(
                new InMemoryRegisteredClientRepository(client),
                new LoginUrlAuthenticationEntryPoint(LoginPaths.LOGIN));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("prompt", "none");
        request.setParameter("client_id", client.getClientId());
        request.setParameter("redirect_uri", requestedRedirectUri);
        request.setParameter("state", STATE);
        MockHttpServletResponse response = new MockHttpServletResponse();

        entryPoint.commence(request, response, new InsufficientAuthenticationException("test"));
        return response;
    }

    private static String promptNoneAuthorizeUri() {
        return OAuth2TestFlows.authorizeUri(promptNoneAuthorizeParams());
    }

    private static Map<String, String> promptNoneAuthorizeParams() {
        Map<String, String> params = OAuth2TestFlows.validAuthorizeParams();
        params.put("prompt", "none");
        params.put("state", STATE);
        return params;
    }
}
