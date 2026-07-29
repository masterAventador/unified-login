package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import com.aventador.unifiedlogin.user.AppUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class JwtClaimsConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Test
    @WithMockUser(username = "claims-sub@example.com")
    void accessTokenSubjectIsUserIdNotEmail() throws Exception {
        String email = "claims-sub@example.com";
        AppUser user = registrationService.register(email, "a valid password");

        Jwt jwt = decodeAccessToken(email);

        assertThat(jwt.getSubject()).isEqualTo(user.getId().toString());
        assertThat(jwt.getSubject()).isNotEqualTo(email);
    }

    @Test
    @WithMockUser(username = "claims-email@example.com")
    void accessTokenCarriesEmailClaim() throws Exception {
        String email = "claims-email@example.com";
        registrationService.register(email, "a valid password");

        Jwt jwt = decodeAccessToken(email);

        assertThat(jwt.getClaimAsString("email")).isEqualTo(email);
    }

    @Test
    @WithMockUser(username = "claims-noroles@example.com")
    void accessTokenCarriesNoRoleOrAuthorityClaim() throws Exception {
        String email = "claims-noroles@example.com";
        registrationService.register(email, "a valid password");

        Jwt jwt = decodeAccessToken(email);

        // 规格书要求：认证中心不下发任何角色或权限信息
        assertThat(jwt.getClaims()).doesNotContainKeys("roles", "authorities", "scope_roles");
    }

    @Test
    @WithMockUser(username = "claims-idtoken@example.com")
    void idTokenSubjectMatchesAccessTokenSubject() throws Exception {
        String email = "claims-idtoken@example.com";
        AppUser user = registrationService.register(email, "a valid password");

        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc, email));

        Jwt idToken = jwtDecoder.decode(OAuth2TestFlows.jsonField(tokenResponse, "id_token"));

        assertThat(idToken.getSubject()).isEqualTo(user.getId().toString());
    }

    private Jwt decodeAccessToken(String email) throws Exception {
        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc, email));

        return jwtDecoder.decode(OAuth2TestFlows.jsonField(tokenResponse, "access_token"));
    }
}
