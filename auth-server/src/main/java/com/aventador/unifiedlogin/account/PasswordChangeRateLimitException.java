package com.aventador.unifiedlogin.account;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.TOO_MANY_REQUESTS,
        reason = "密码验证尝试过于频繁，请稍后再试")
public class PasswordChangeRateLimitException extends RuntimeException {

    public PasswordChangeRateLimitException() {
        super("密码验证尝试过于频繁，请稍后再试");
    }
}
