package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class OidcEndpointsTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void discoveryDocumentIsPubliclyAvailable() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").exists())
                .andExpect(jsonPath("$.authorization_endpoint").exists())
                .andExpect(jsonPath("$.token_endpoint").exists())
                .andExpect(jsonPath("$.jwks_uri").exists())
                .andExpect(jsonPath("$.userinfo_endpoint").exists());
    }

    @Test
    void discoveryAdvertisesAuthorizationCodeAndRefreshTokenGrants() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.grant_types_supported").value(
                        org.hamcrest.Matchers.hasItems("authorization_code", "refresh_token")));
    }

    @Test
    void jwksEndpointExposesPublicKeyWithoutPrivateMaterial() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].n").exists())
                .andExpect(jsonPath("$.keys[0].kid").exists())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist());
    }

    @Test
    void authorizationEndpointIsAccessible() throws Exception {
        // authorize 端点存在且在处理请求，返回 4xx 证明端点存在（而不是 404）
        var result = mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "demo-web-a"))
                .andReturn();
        // 确保端点存在，不返回 404
        int status = result.getResponse().getStatus();
        if (status == 404) {
            throw new AssertionError("authorize endpoint not found (404)");
        }
    }
}
