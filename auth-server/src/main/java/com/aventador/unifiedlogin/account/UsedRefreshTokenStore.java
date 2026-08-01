package com.aventador.unifiedlogin.account;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

/**
 * 记录已经成功消费的刷新令牌，用于识别一次性令牌重放。
 *
 * <p>这里只落库 SHA-256 指纹，不保存能换取凭证的原始令牌。刷新令牌由 96 个随机字节
 * 生成，无法通过低熵字典反推；记录保留到原令牌自然过期，之后由后续轮转顺手清理。
 */
@Component
public class UsedRefreshTokenStore {

    private final JdbcTemplate jdbcTemplate;

    public UsedRefreshTokenStore(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Optional<UUID> findUnexpiredUserId(String refreshToken) {
        return jdbcTemplate.queryForList("""
                SELECT user_id
                FROM oauth2_used_refresh_token
                WHERE token_hash = ?
                  AND expires_at > CURRENT_TIMESTAMP
                """, UUID.class, fingerprint(refreshToken)).stream().findFirst();
    }

    public void record(String refreshToken, UUID userId, Instant expiresAt) {
        jdbcTemplate.update("""
                DELETE FROM oauth2_used_refresh_token
                WHERE expires_at <= CURRENT_TIMESTAMP
                """);
        jdbcTemplate.update("""
                INSERT INTO oauth2_used_refresh_token (token_hash, user_id, expires_at)
                VALUES (?, ?, ?)
                ON CONFLICT (token_hash) DO NOTHING
                """, fingerprint(refreshToken), userId, Timestamp.from(expiresAt));
    }

    private static String fingerprint(String refreshToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(refreshToken.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("JVM 不支持必需的 SHA-256 摘要算法", ex);
        }
    }
}
