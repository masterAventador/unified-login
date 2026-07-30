package com.aventador.unifiedlogin.web;

import com.aventador.unifiedlogin.security.LoginPaths;
import com.aventador.unifiedlogin.security.LoginRateLimitProperties;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    private final LoginRateLimitProperties rateLimitProperties;

    public LoginController(LoginRateLimitProperties rateLimitProperties) {
        this.rateLimitProperties = rateLimitProperties;
    }

    @GetMapping(LoginPaths.LOGIN)
    public String showLoginPage(Model model) {
        // 锁定时长交给模板渲染而不是写死在文案里：运维把时长调成 30 分钟后，
        // 页面若仍然写「15 分钟」，用户按提示回来会发现还是登不进去
        model.addAttribute("lockMinutes", rateLimitProperties.emailLockDuration().toMinutes());
        return "login";
    }
}
