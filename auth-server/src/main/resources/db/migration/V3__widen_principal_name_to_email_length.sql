-- V2 的这两张表照抄自框架官方 schema，principal_name 是 varchar(200)。
-- 本系统的主体名就是用户邮箱，而邮箱上限是 320（EmailAddress.MAX_LENGTH / app_user.email）。
-- 两者不一致时，超过 200 字符的邮箱能注册成功、能登录成功，直到走授权端点写入本表才 500，
-- 表现为「账号能登录但打开任何产品都报错」，且账号自身无法自助修复。
ALTER TABLE oauth2_authorization ALTER COLUMN principal_name TYPE varchar(320);

ALTER TABLE oauth2_authorization_consent ALTER COLUMN principal_name TYPE varchar(320);
