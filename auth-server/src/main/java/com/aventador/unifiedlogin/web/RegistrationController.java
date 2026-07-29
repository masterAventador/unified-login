package com.aventador.unifiedlogin.web;

import com.aventador.unifiedlogin.password.WeakPasswordException;
import com.aventador.unifiedlogin.registration.EmailAlreadyRegisteredException;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.user.InvalidEmailException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class RegistrationController {

    private final RegistrationService registrationService;

    public RegistrationController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @GetMapping("/register")
    public String showRegistrationPage() {
        return "register";
    }

    @PostMapping("/register")
    public String submitRegistration(@RequestParam String email,
                                     @RequestParam String password,
                                     Model model) {
        try {
            registrationService.register(email, password);
            return "redirect:/login?registered";
        }
        catch (InvalidEmailException | WeakPasswordException | EmailAlreadyRegisteredException ex) {
            model.addAttribute("errorMessage", ex.getMessage());
            model.addAttribute("email", email);
            return "register";
        }
    }
}
