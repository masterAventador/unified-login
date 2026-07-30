package com.aventador.unifiedlogin.account;

public class IncorrectCurrentPasswordException extends RuntimeException {

    public IncorrectCurrentPasswordException() {
        super("当前密码不正确");
    }
}
