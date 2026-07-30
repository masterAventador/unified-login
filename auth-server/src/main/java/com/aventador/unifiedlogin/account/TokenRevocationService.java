package com.aventador.unifiedlogin.account;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * 以用户为边界撤销授权服务器持久化的全部令牌。
 *
 * <p>{@code oauth2_authorization.principal_name} 保存的是规范化邮箱而不是用户 UUID，
 * 因此通过 {@code app_user} 子查询在数据库内完成 UUID 到邮箱的定位。删除整条授权记录
 * 会立即使其中的 refresh token 无法再被令牌端点查到；已经签发的自包含 access token
 * 仍按其剩余有效期自然失效。
 */
@Service
public class TokenRevocationService {

    private final JdbcTemplate jdbcTemplate;

    private final UserTokenLock userTokenLock;

    public TokenRevocationService(JdbcTemplate jdbcTemplate, UserTokenLock userTokenLock) {
        this.jdbcTemplate = jdbcTemplate;
        this.userTokenLock = userTokenLock;
    }

    @Transactional
    public void revokeAllTokensOf(UUID userId) {
        userTokenLock.lockByUserId(userId).ifPresent(this::deleteAuthorizationsOf);
    }

    private void deleteAuthorizationsOf(String principalName) {
        jdbcTemplate.update("""
                DELETE FROM oauth2_authorization
                WHERE principal_name = ?
                """, principalName);
    }
}
