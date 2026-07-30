package com.aventador.unifiedlogin.account;

import com.aventador.unifiedlogin.password.PasswordPolicy;
import com.aventador.unifiedlogin.security.LoginAttemptService;
import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.AppUserRepository;
import com.aventador.unifiedlogin.user.EmailAddress;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class PasswordChangeService {

    private final AppUserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final TokenRevocationService tokenRevocationService;

    private final LoginAttemptService loginAttemptService;

    private final UserTokenLock userTokenLock;

    public PasswordChangeService(
            AppUserRepository userRepository,
            PasswordEncoder passwordEncoder,
            TokenRevocationService tokenRevocationService,
            LoginAttemptService loginAttemptService,
            UserTokenLock userTokenLock) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenRevocationService = tokenRevocationService;
        this.loginAttemptService = loginAttemptService;
        this.userTokenLock = userTokenLock;
    }

    @Transactional
    public void changePassword(String email, String currentPassword, String newPassword) {
        String normalizedEmail = EmailAddress.normalize(email);
        if (!userTokenLock.lockByPrincipalName(normalizedEmail)) {
            throw new IncorrectCurrentPasswordException();
        }
        if (loginAttemptService.isLocked(normalizedEmail)) {
            throw new PasswordChangeRateLimitException();
        }
        AppUser user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(IncorrectCurrentPasswordException::new);
        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            loginAttemptService.recordFailure(normalizedEmail);
            throw new IncorrectCurrentPasswordException();
        }
        PasswordPolicy.validate(newPassword);

        Instant changedAt = Instant.now();
        user.changePassword(passwordEncoder.encode(newPassword), changedAt);
        tokenRevocationService.revokeAllTokensOf(user.getId());
        loginAttemptService.clearFailures(normalizedEmail);
    }
}
