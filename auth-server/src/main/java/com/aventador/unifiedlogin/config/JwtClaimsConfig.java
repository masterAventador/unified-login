package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.EmailAddress;
import com.aventador.unifiedlogin.user.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

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
            AppUser user = userService.findByEmail(new EmailAddress(context.getPrincipal().getName()))
                    .orElseThrow(() -> new IllegalStateException("签发令牌时找不到对应用户"));

            context.getClaims().subject(user.getId().toString());
            context.getClaims().claim("email", user.getEmail());
        };
    }
}
