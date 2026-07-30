package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.EmailAddress;
import com.aventador.unifiedlogin.user.UserService;
import com.aventador.unifiedlogin.user.UserStatus;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;
import java.util.Base64;

@Configuration
public class JwtClaimsConfig {

    private final UserService userService;

    public JwtClaimsConfig(UserService userService) {
        this.userService = userService;
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            String tokenType = context.getTokenType().getValue();
            boolean isAccessToken = OAuth2TokenType.ACCESS_TOKEN.getValue().equals(tokenType);
            boolean isIdToken = OidcParameterNames.ID_TOKEN.equals(tokenType);
            if (!isAccessToken && !isIdToken) {
                return;
            }

            // 注意：刷新令牌授权时 principal 是首次登录时序列化进 oauth2_authorization 表的
            // 快照，最长可在 refresh token 的 30 天寿命内被反复复用。因此这里的查找 key 是
            // 「登录时刻的邮箱」而非当前邮箱——将来实现「修改邮箱」功能时必须同步处理这里
            // （改完邮箱后旧 refresh token 会查不到人），否则表现为改邮箱即被强制登出。
            //
            // 查不到用户说明账号在授权码 / refresh token 仍有效的窗口内被删掉了，属于「授权已失效」
            // 而不是服务端故障，必须抛 OAuth2AuthenticationException 让令牌端点回标准错误体——
            // 抛其它异常会穿过整条认证链变成 500，接入方按规范解析 JSON 错误体时会直接失败。
            AppUser user = userService.findByEmail(new EmailAddress(context.getPrincipal().getName()))
                    .orElseThrow(() -> new OAuth2AuthenticationException(
                            new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "签发令牌时找不到对应用户", null)));
            if (user.getStatus() != UserStatus.ACTIVE) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "签发令牌时账号不可用", null));
            }

            context.getClaims().subject(user.getId().toString());
            context.getClaims().claim("email", user.getEmail());
        };
    }

    /**
     * 自定义令牌生成器。**存在的唯一理由**是绕开框架对公有客户端的 refresh token 拦截：
     * {@code OAuth2RefreshTokenGenerator} 在「authorization_code + ClientAuthenticationMethod.NONE」
     * 时直接返回 null，而本系统所有接入方都必须是公有客户端，照默认走会拿不到 refresh token。
     * OAuth 2.1 允许公有客户端使用 refresh token，前提是必须轮转——本系统已启用
     * 一次性轮转（reuseRefreshTokens(false)），满足该前提。
     *
     * 注意：一旦自定义此 bean，框架不再自动装配 OAuth2TokenCustomizer，
     * 必须在这里手动 setJwtCustomizer，否则 sub/email 定制会静默失效。
     *
     * <p><b>有意未复现框架的 DefaultOAuth2TokenCustomizers</b>：框架默认还会装一个内部
     * customizer，负责 mTLS 证书绑定的 {@code cnf.x5t#S256}、DPoP 的 {@code cnf.jkt}、
     * 以及令牌交换的 {@code act} 三个声明。该类是框架包内可见，无法直接引用。本系统这三个
     * 特性一个都没启用，故不复现。**启用其中任何一个之前必须回到这里补齐**——否则表现为
     * 令牌照常签发、状态码照常 200，但发送方绑定静默失效，令牌退化为纯 bearer。
     * 同理，若将来把某个客户端的令牌格式改成 opaque，需要给 OAuth2AccessTokenGenerator
     * 装上对应的 OAuth2TokenCustomizer&lt;OAuth2TokenClaimsContext&gt;。
     */
    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(
            JWKSource<SecurityContext> jwkSource,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator,
                new OAuth2AccessTokenGenerator(),
                new PublicClientRefreshTokenGenerator());
    }

    /** 与框架实现逐行等价，仅去掉「公有客户端不发 refresh token」那条拦截。 */
    private static final class PublicClientRefreshTokenGenerator
            implements OAuth2TokenGenerator<OAuth2RefreshToken> {

        private static final int TOKEN_BYTE_LENGTH = 96;

        private final StringKeyGenerator keyGenerator =
                new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), TOKEN_BYTE_LENGTH);

        @Override
        public OAuth2RefreshToken generate(OAuth2TokenContext context) {
            if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                return null;
            }
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plus(
                    context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
            return new OAuth2RefreshToken(keyGenerator.generateKey(), issuedAt, expiresAt);
        }
    }
}
