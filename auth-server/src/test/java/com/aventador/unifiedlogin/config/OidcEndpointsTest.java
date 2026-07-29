package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.file.Path;

import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class OidcEndpointsTest {

    // 密钥文件指向临时目录：避免测试在项目目录里落下真实私钥，
    // 也保证「生成」分支每次运行都被真实执行而非复用陈旧文件
    @TempDir
    static Path keyDir;

    @DynamicPropertySource
    static void isolatedKeyStore(DynamicPropertyRegistry registry) {
        registry.add("unified-login.jwt-key-store",
                () -> keyDir.resolve("jwt-signing-key.json").toString());
    }

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
        // RSA 私钥在 JWK 里共六个字段，漏断言任何一个都可能放过泄漏
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].n").exists())
                .andExpect(jsonPath("$.keys[0].kid").exists())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())
                .andExpect(jsonPath("$.keys[0].q").doesNotExist())
                .andExpect(jsonPath("$.keys[0].dp").doesNotExist())
                .andExpect(jsonPath("$.keys[0].dq").doesNotExist())
                .andExpect(jsonPath("$.keys[0].qi").doesNotExist());
    }

    @Test
    void userinfoWithoutTokenReturnsUnauthorized() throws Exception {
        // 401 + Bearer 挑战头证明资源服务器过滤器已接上；配置缺失时这里会是 403 或 302
        mockMvc.perform(get("/userinfo").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", startsWith("Bearer")));
    }

    @Test
    void authorizationEndpointRedirectsAnonymousUserToLogin() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "demo-web-a")
                        .param("redirect_uri", "http://localhost:5173/callback")
                        .param("scope", "openid")
                        .param("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection());
    }
}
