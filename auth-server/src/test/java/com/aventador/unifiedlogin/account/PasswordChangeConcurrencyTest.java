package com.aventador.unifiedlogin.account;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Import({PostgresTestConfig.class, PasswordChangeConcurrencyTest.PasswordEncoderTestConfig.class})
class PasswordChangeConcurrencyTest {

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private PasswordChangeService passwordChangeService;

    @Autowired
    private PausingPasswordEncoder passwordEncoder;

    @Test
    void onlyOneConcurrentRequestCanUseTheSameCurrentPassword() throws Exception {
        String email = "concurrent-password-change@example.com";
        String currentPassword = "current password";
        registrationService.register(email, currentPassword);
        passwordEncoder.pauseNextTwoMatches();

        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            Future<Throwable> first = executor.submit(() ->
                    changePasswordAfter(start, email, currentPassword, "first new password"));
            Future<Throwable> second = executor.submit(() ->
                    changePasswordAfter(start, email, currentPassword, "second new password"));
            start.countDown();

            List<Throwable> outcomes = Arrays.asList(
                    first.get(5, TimeUnit.SECONDS),
                    second.get(5, TimeUnit.SECONDS));
            assertThat(outcomes).filteredOn((outcome) -> outcome == null).hasSize(1);
            assertThat(outcomes).filteredOn(IncorrectCurrentPasswordException.class::isInstance).hasSize(1);
        }
        finally {
            executor.shutdownNow();
        }
    }

    private Throwable changePasswordAfter(
            CountDownLatch start,
            String email,
            String currentPassword,
            String newPassword) {
        try {
            start.await();
            passwordChangeService.changePassword(email, currentPassword, newPassword);
            return null;
        }
        catch (Throwable throwable) {
            return throwable;
        }
    }

    static class PasswordEncoderTestConfig {

        @Bean
        @Primary
        PausingPasswordEncoder pausingPasswordEncoder() {
            return new PausingPasswordEncoder(
                    new Argon2PasswordEncoder(16, 32, 1, 19456, 2));
        }
    }

    static final class PausingPasswordEncoder implements PasswordEncoder {

        private final PasswordEncoder delegate;

        private final AtomicBoolean armed = new AtomicBoolean();

        private volatile CountDownLatch matchingRequests = new CountDownLatch(0);

        PausingPasswordEncoder(PasswordEncoder delegate) {
            this.delegate = delegate;
        }

        void pauseNextTwoMatches() {
            matchingRequests = new CountDownLatch(2);
            armed.set(true);
        }

        @Override
        public String encode(CharSequence rawPassword) {
            return delegate.encode(rawPassword);
        }

        @Override
        public boolean matches(CharSequence rawPassword, String encodedPassword) {
            if (armed.get()) {
                CountDownLatch requests = matchingRequests;
                requests.countDown();
                try {
                    requests.await(500, TimeUnit.MILLISECONDS);
                }
                catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("并发密码校验被中断", ex);
                }
                if (requests.getCount() == 0) {
                    armed.set(false);
                }
            }
            return delegate.matches(rawPassword, encodedPassword);
        }
    }
}
