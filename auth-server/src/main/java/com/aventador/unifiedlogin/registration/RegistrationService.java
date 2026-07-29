package com.aventador.unifiedlogin.registration;

import com.aventador.unifiedlogin.password.PasswordPolicy;
import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.EmailAddress;
import com.aventador.unifiedlogin.user.UserService;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class RegistrationService {

    private static final String EMAIL_TAKEN_MESSAGE = "该邮箱已被注册";

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public RegistrationService(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    public AppUser register(String rawEmail, String rawPassword) {
        EmailAddress email = new EmailAddress(rawEmail);
        PasswordPolicy.validate(rawPassword);

        if (userService.emailExists(email)) {
            throw new EmailAlreadyRegisteredException(EMAIL_TAKEN_MESSAGE);
        }

        try {
            return userService.createUser(email, passwordEncoder.encode(rawPassword));
        }
        catch (DataIntegrityViolationException ex) {
            // 并发注册同一邮箱穿过了上面的查重，唯一索引兜底后在此转译
            throw new EmailAlreadyRegisteredException(EMAIL_TAKEN_MESSAGE);
        }
    }

    public boolean isEmailTaken(String rawEmail) {
        return userService.emailExists(new EmailAddress(rawEmail));
    }
}
