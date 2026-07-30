package com.aventador.unifiedlogin.account;

import com.aventador.unifiedlogin.password.WeakPasswordException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;

@Controller
public class PasswordChangeController {

    private final PasswordChangeService passwordChangeService;

    public PasswordChangeController(PasswordChangeService passwordChangeService) {
        this.passwordChangeService = passwordChangeService;
    }

    @GetMapping("/account/password")
    public String showPasswordChangePage() {
        return "account/password";
    }

    @PostMapping("/account/password")
    public String changePassword(
            @RequestParam String currentPassword,
            @RequestParam String newPassword,
            Principal principal,
            Model model,
            RedirectAttributes redirectAttributes) {
        try {
            passwordChangeService.changePassword(principal.getName(), currentPassword, newPassword);
            redirectAttributes.addFlashAttribute("passwordChanged", true);
            return "redirect:/account/password";
        }
        catch (IncorrectCurrentPasswordException | WeakPasswordException ex) {
            model.addAttribute("errorMessage", ex.getMessage());
            return "account/password";
        }
    }
}
