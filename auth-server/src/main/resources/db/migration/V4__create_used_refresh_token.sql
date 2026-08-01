-- 刷新令牌轮转后，oauth2_authorization 只保留新令牌，旧令牌与用户之间的关系随即丢失。
-- 保存旧令牌的不可逆指纹，才能把再次提交识别为泄漏并撤销该用户的全部会话。
--
-- 不设置 app_user 外键：账号删除后又用同一邮箱注册时是全新的用户 UUID，旧令牌重放
-- 绝不能误伤新账号；记录保留至原令牌到期，期间即使用户已删除也仍可安全识别重放。
CREATE TABLE oauth2_used_refresh_token (
    token_hash char(64)    NOT NULL,
    user_id    uuid        NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (token_hash)
);

CREATE INDEX ix_oauth2_used_refresh_token_expires_at
    ON oauth2_used_refresh_token (expires_at);
