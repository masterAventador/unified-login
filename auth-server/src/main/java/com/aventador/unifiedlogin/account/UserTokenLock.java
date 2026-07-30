package com.aventador.unifiedlogin.account;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

/**
 * 用用户行锁串行化同一账号的 refresh token 轮转与全量撤销。
 *
 * <p>锁必须由调用方在覆盖整个令牌操作的数据库事务内持有。使用数据库行锁而非 JVM 锁，
 * 是为了多实例部署时仍只有一条同账号令牌操作能够进入临界区；不同用户落在不同行上，
 * 彼此不会被无谓串行化。
 */
@Component
public class UserTokenLock {

    private final JdbcTemplate jdbcTemplate;

    public UserTokenLock(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Optional<String> lockByUserId(UUID userId) {
        return jdbcTemplate.queryForList("""
                SELECT email
                FROM app_user
                WHERE id = ?
                FOR UPDATE
                """, String.class, userId).stream().findFirst();
    }

    public boolean lockByPrincipalName(String principalName) {
        return !jdbcTemplate.queryForList("""
                SELECT true
                FROM app_user
                WHERE email = ?
                FOR UPDATE
                """, Boolean.class, principalName).isEmpty();
    }
}
