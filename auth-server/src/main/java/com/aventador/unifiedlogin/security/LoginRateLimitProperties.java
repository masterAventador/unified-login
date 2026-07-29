package com.aventador.unifiedlogin.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "unified-login.login-rate-limit")
public record LoginRateLimitProperties(int maxFailuresPerEmail,
                                       Duration emailLockDuration,
                                       int maxAttemptsPerIpPerMinute) {
}
