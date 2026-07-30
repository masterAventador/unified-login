package com.aventador.unifiedlogin.admin;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class AdminUserNotFoundException extends RuntimeException {
}
