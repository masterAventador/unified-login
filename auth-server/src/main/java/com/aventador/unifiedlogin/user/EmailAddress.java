package com.aventador.unifiedlogin.user;

import java.util.Locale;
import java.util.regex.Pattern;

public record EmailAddress(String value) {

    public static final int MAX_LENGTH = 320;

    private static final Pattern PATTERN = Pattern.compile("^[^@\\s]+@[^@\\s.]+(\\.[^@\\s.]+)+$");

    public EmailAddress {
        if (value == null) {
            throw new InvalidEmailException("邮箱不能为空");
        }
        value = normalize(value);
        if (value.isEmpty()) {
            throw new InvalidEmailException("邮箱不能为空");
        }
        if (value.length() > MAX_LENGTH) {
            throw new InvalidEmailException("邮箱长度不能超过 " + MAX_LENGTH + " 个字符");
        }
        if (!PATTERN.matcher(value).matches()) {
            throw new InvalidEmailException("邮箱格式不正确");
        }
    }

    /**
     * 只做规范化，不做任何校验。用于必须对非法输入也一致处理的场景——
     * 例如登录失败限流，对不存在或格式错误的邮箱同样要计数，否则「会不会被锁」
     * 本身就泄漏了账号是否存在。
     */
    public static String normalize(String raw) {
        return (raw == null) ? "" : raw.trim().toLowerCase(Locale.ROOT);
    }
}
