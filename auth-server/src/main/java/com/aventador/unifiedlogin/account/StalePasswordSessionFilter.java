package com.aventador.unifiedlogin.account;

import com.aventador.unifiedlogin.user.AppUserRepository;
import com.aventador.unifiedlogin.user.EmailAddress;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

public class StalePasswordSessionFilter extends OncePerRequestFilter {

    private static final RequestMatcher AUTHORIZATION_ENDPOINT =
            PathPatternRequestMatcher.withDefaults().matcher("/oauth2/authorize");

    private final AppUserRepository userRepository;

    public StalePasswordSessionFilter(AppUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && isOlderThanCurrentPassword(authentication)) {
            SecurityContextHolder.clearContext();
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !AUTHORIZATION_ENDPOINT.matches(request);
    }

    private boolean isOlderThanCurrentPassword(Authentication authentication) {
        Optional<Instant> passwordAuthenticationTime = authentication.getAuthorities().stream()
                .filter(FactorGrantedAuthority.class::isInstance)
                .map(FactorGrantedAuthority.class::cast)
                .filter((authority) -> FactorGrantedAuthority.PASSWORD_AUTHORITY
                        .equals(authority.getAuthority()))
                .map(FactorGrantedAuthority::getIssuedAt)
                .findFirst();
        if (passwordAuthenticationTime.isEmpty()) {
            return false;
        }

        return userRepository.findByEmail(EmailAddress.normalize(authentication.getName()))
                .map((user) -> user.getPasswordChangedAt().isAfter(passwordAuthenticationTime.get()))
                .orElse(true);
    }
}
