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

            AppUser user = userService.findByEmail(new EmailAddress(context.getPrincipal().getName()))
                    .orElseThrow(() -> new IllegalStateException("签发令牌时找不到对应用户"));

            context.getClaims().subject(user.getId().toString());
            context.getClaims().claim("email", user.getEmail());
        };
    }
}
