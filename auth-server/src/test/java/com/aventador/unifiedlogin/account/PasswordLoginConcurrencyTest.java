package com.aventador.unifiedlogin.account;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;

/**
 * 表单登录必须与改密、后台重置密码共用同一用户行锁。
 *
 * <p>否则登录可以先读到旧 hash，等改密提交后再完成密码校验。此时框架记录的
 * {@code FACTOR_PASSWORD.issuedAt} 反而晚于 {@code passwordChangedAt}，旧密码登录得到的会话
 * 会绕过后续的过期判断。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import({
        PostgresTestConfig.class,
        PasswordLoginConcurrencyTest.PausingPasswordEncoderConfig.class
})
class PasswordLoginConcurrencyTest {

    private static final String EMAIL = "password-login-race@example.com";

    private static final String PASSWORD = "a valid password";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private PausingPasswordEncoder passwordEncoder;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void formLoginHoldsUserLockUntilPasswordAuthenticationCompletes() throws Exception {
        registrationService.register(EMAIL, PASSWORD);
        passwordEncoder.pauseNextMatch();

        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<MvcResult> login = executor.submit(() ->
                    mockMvc.perform(formLogin("/login").user(EMAIL).password(PASSWORD))
                            .andReturn());
            assertThat(passwordEncoder.awaitPausedMatch())
                    .as("表单登录应停在旧密码校验中")
                    .isTrue();

            TransactionTemplate competingTransaction = new TransactionTemplate(transactionManager);
            Throwable lockAttempt = catchThrowable(() ->
                    competingTransaction.executeWithoutResult((status) ->
                            jdbcTemplate.queryForObject("""
                                    SELECT true
                                    FROM app_user
                                    WHERE email = ?
                                    FOR UPDATE NOWAIT
                                    """, Boolean.class, EMAIL)));

            assertThat(lockAttempt)
                    .as("密码校验完成前，表单登录必须持有该用户的数据库行锁")
                    .isInstanceOf(DataAccessException.class);

            passwordEncoder.resumeMatch();
            assertThat(login.get(10, TimeUnit.SECONDS).getResponse().getStatus()).isEqualTo(302);
        }
        finally {
            passwordEncoder.resumeMatch();
            executor.shutdownNow();
        }
    }

    @org.springframework.boot.test.context.TestConfiguration(proxyBeanMethods = false)
    static class PausingPasswordEncoderConfig {

        @Bean
        @Primary
        PausingPasswordEncoder pausingPasswordEncoder() {
            return new PausingPasswordEncoder(
                    new Argon2PasswordEncoder(16, 32, 1, 19456, 2));
        }
    }

    static final class PausingPasswordEncoder implements PasswordEncoder {

        private final PasswordEncoder delegate;

        private final AtomicReference<MatchPause> nextPause = new AtomicReference<>();

        PausingPasswordEncoder(PasswordEncoder delegate) {
            this.delegate = delegate;
        }

        void pauseNextMatch() {
            assertThat(nextPause.compareAndSet(null, new MatchPause())).isTrue();
        }

        boolean awaitPausedMatch() throws InterruptedException {
            MatchPause pause = nextPause.get();
            return pause != null && pause.entered().await(10, TimeUnit.SECONDS);
        }

        void resumeMatch() {
            MatchPause pause = nextPause.get();
            if (pause != null) {
                pause.resume().countDown();
            }
        }

        @Override
        public String encode(CharSequence rawPassword) {
            return delegate.encode(rawPassword);
        }

        @Override
        public boolean matches(CharSequence rawPassword, String encodedPassword) {
            MatchPause pause = nextPause.get();
            if (pause != null) {
                pause.entered().countDown();
                try {
                    if (!pause.resume().await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("等待放行密码校验超时");
                    }
                }
                catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("等待放行密码校验时被中断", ex);
                }
                finally {
                    nextPause.compareAndSet(pause, null);
                }
            }
            return delegate.matches(rawPassword, encodedPassword);
        }
    }

    private record MatchPause(CountDownLatch entered, CountDownLatch resume) {

        private MatchPause() {
            this(new CountDownLatch(1), new CountDownLatch(1));
        }
    }
}
