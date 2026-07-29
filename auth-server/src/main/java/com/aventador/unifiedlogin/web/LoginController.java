package com.aventador.unifiedlogin.web;

import com.aventador.unifiedlogin.security.LoginPaths;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping(LoginPaths.LOGIN)
    public String showLoginPage() {
        return "login";
    }
}
