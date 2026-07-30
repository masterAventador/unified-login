package com.aventador.unifiedlogin.admin;

import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.AppUserRepository;
import com.aventador.unifiedlogin.user.UserStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * 管理接口的准入判据：令牌签给管理后台，且当前有效身份在用户表中仍是平台管理员。
 *
 * <p>管理 SPA 使用 access token，JWT 的 {@code sub} 是用户 UUID。管理 API 不接受
 * 认证中心表单会话代替 Bearer token，否则后续为无状态 API 关闭 CSRF 时，会把浏览器
 * Cookie 身份意外暴露给跨站请求。管理员标记必须逐次回查数据库，不能塞进长寿命令牌，
 * 否则撤销管理员资格后旧 token 仍可继续操作后台。
 */
@Component
public class PlatformAdminGuard implements AuthorizationManager<RequestAuthorizationContext> {

    private final AppUserRepository userRepository;

    public PlatformAdminGuard(AppUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public AuthorizationResult authorize(
            Supplier<? extends Authentication> authenticationSupplier,
            RequestAuthorizationContext context) {
        Authentication authentication = authenticationSupplier.get();
        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return new AuthorizationDecision(false);
        }

        if (!(authentication.getPrincipal() instanceof Jwt jwt)) {
            return new AuthorizationDecision(false);
        }

        // 平台管理员可能同时使用多个产品。只查 sub 会让任意低信任客户端签发的令牌
        // 横向升级成管理令牌，破坏 OAuth audience 隔离。
        if (!jwt.getAudience().contains(AdminClient.CLIENT_ID)) {
            return new AuthorizationDecision(false);
        }

        boolean platformAdmin = findUser(jwt)
                .map((user) -> user.isPlatformAdmin() && user.getStatus() == UserStatus.ACTIVE)
                .orElse(false);
        return new AuthorizationDecision(platformAdmin);
    }

    private Optional<AppUser> findUser(Jwt jwt) {
        try {
            return this.userRepository.findById(UUID.fromString(jwt.getSubject()));
        }
        catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }
}
