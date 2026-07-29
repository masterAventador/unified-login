package com.aventador.unifiedlogin.security;

import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.EmailAddress;
import com.aventador.unifiedlogin.user.InvalidEmailException;
import com.aventador.unifiedlogin.user.UserService;
import com.aventador.unifiedlogin.user.UserStatus;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class AppUserDetailsService implements UserDetailsService {

    private static final String NOT_FOUND_MESSAGE = "邮箱或密码不正确";

    private final UserService userService;

    public AppUserDetailsService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        EmailAddress email;
        try {
            email = new EmailAddress(username);
        }
        catch (InvalidEmailException ex) {
            throw new UsernameNotFoundException(NOT_FOUND_MESSAGE);
        }

        AppUser user = userService.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(NOT_FOUND_MESSAGE));

        return User.withUsername(user.getEmail())
                .password(user.getPasswordHash())
                .disabled(user.getStatus() == UserStatus.DISABLED)
                .authorities(Collections.emptyList())
                .build();
    }
}
