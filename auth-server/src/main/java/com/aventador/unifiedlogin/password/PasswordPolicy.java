package com.aventador.unifiedlogin.password;

public final class PasswordPolicy {

    public static final int MIN_LENGTH = 8;
    public static final int MAX_LENGTH = 64;

    private PasswordPolicy() {
    }

    public static void validate(String rawPassword) {
        if (rawPassword == null) {
            throw new WeakPasswordException("密码不能为空");
        }
        if (rawPassword.length() < MIN_LENGTH) {
            throw new WeakPasswordException("密码长度不能少于 " + MIN_LENGTH + " 个字符");
        }
        if (rawPassword.length() > MAX_LENGTH) {
            throw new WeakPasswordException("密码长度不能超过 " + MAX_LENGTH + " 个字符");
        }
    }
}
