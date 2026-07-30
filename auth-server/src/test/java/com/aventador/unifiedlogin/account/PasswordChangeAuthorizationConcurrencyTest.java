package com.aventador.unifiedlogin.account;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import({
        PostgresTestConfig.class,
        PasswordChangeAuthorizationConcurrencyTest.PausingAuthorizationConfig.class
})
class PasswordChangeAuthorizationConcurrencyTest {

    private static final String CURRENT_PASSWORD = "current password";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private PasswordChangeService passwordChangeService;

    @Autowired
    private PausingAuthorizationService authorizationService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Test
    void authorizationSavedAfterPasswordChangeCannotBeExchangedForTokens() throws Exception {
        String email = "password-change-authorization-race@example.com";
        registrationService.register(email, CURRENT_PASSWORD);
        MockHttpSession staleSession = OAuth2TestFlows.login(mockMvc, email, CURRENT_PASSWORD);
        authorizationService.pauseNextSave();

        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<String> authorizationCode = executor.submit(
                    () -> OAuth2TestFlows.authorizeAndExtractCode(mockMvc, staleSession));
            assertThat(authorizationService.awaitPausedSave())
                    .as("旧会话的授权请求应停在授权码持久化之前")
                    .isTrue();

            passwordChangeService.changePassword(
                    email, CURRENT_PASSWORD, "new valid password");
            authorizationService.resumeSave();
            String code = authorizationCode.get(10, TimeUnit.SECONDS);

            mockMvc.perform(post("/oauth2/token")
                            .param("grant_type", "authorization_code")
                            .param("client_id", OAuth2TestFlows.CLIENT_ID)
                            .param("code", code)
                            .param("redirect_uri", OAuth2TestFlows.REDIRECT_URI)
                            .param("code_verifier", OAuth2TestFlows.CODE_VERIFIER))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("invalid_grant"))
                    .andExpect(jsonPath("$.access_token").doesNotExist())
                    .andExpect(jsonPath("$.refresh_token").doesNotExist())
                    .andExpect(jsonPath("$.id_token").doesNotExist());
        }
        finally {
            authorizationService.resumeSave();
            executor.shutdownNow();
        }
    }

    @Test
    void authorizationCodeExchangeHoldsUserLockUntilAuthorizationSave() throws Exception {
        String email = "password-change-token-save-race@example.com";
        registrationService.register(email, CURRENT_PASSWORD);
        MockHttpSession session = OAuth2TestFlows.login(mockMvc, email, CURRENT_PASSWORD);
        String code = OAuth2TestFlows.authorizeAndExtractCode(mockMvc, session);
        authorizationService.pauseNextSave();

        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<Integer> tokenStatus = executor.submit(() -> mockMvc.perform(post("/oauth2/token")
                            .param("grant_type", "authorization_code")
                            .param("client_id", OAuth2TestFlows.CLIENT_ID)
                            .param("code", code)
                            .param("redirect_uri", OAuth2TestFlows.REDIRECT_URI)
                            .param("code_verifier", OAuth2TestFlows.CODE_VERIFIER))
                    .andReturn()
                    .getResponse()
                    .getStatus());
            assertThat(authorizationService.awaitPausedSave())
                    .as("授权码兑换应停在最终授权持久化之前")
                    .isTrue();

            TransactionTemplate competingTransaction = new TransactionTemplate(transactionManager);
            assertThat(org.assertj.core.api.Assertions.catchThrowable(() ->
                    competingTransaction.executeWithoutResult((status) ->
                            jdbcTemplate.queryForObject("""
                                    SELECT true
                                    FROM app_user
                                    WHERE email = ?
                                    FOR UPDATE NOWAIT
                                    """, Boolean.class, email))))
                    .as("最终保存尚未完成时，授权码兑换必须仍持有同一用户行锁")
                    .isInstanceOf(DataAccessException.class);

            authorizationService.resumeSave();
            assertThat(tokenStatus.get(10, TimeUnit.SECONDS)).isEqualTo(200);
        }
        finally {
            authorizationService.resumeSave();
            executor.shutdownNow();
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class PausingAuthorizationConfig {

        @Bean
        @Primary
        PausingAuthorizationService pausingAuthorizationService(
                JdbcTemplate jdbcTemplate,
                RegisteredClientRepository registeredClientRepository) {
            return new PausingAuthorizationService(
                    new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository));
        }
    }

    static final class PausingAuthorizationService implements OAuth2AuthorizationService {

        private final OAuth2AuthorizationService delegate;

        private final AtomicReference<SavePause> nextSave = new AtomicReference<>();

        private PausingAuthorizationService(OAuth2AuthorizationService delegate) {
            this.delegate = delegate;
        }

        void pauseNextSave() {
            assertThat(nextSave.compareAndSet(null, new SavePause())).isTrue();
        }

        boolean awaitPausedSave() throws InterruptedException {
            SavePause pause = nextSave.get();
            return pause != null && pause.entered().await(10, TimeUnit.SECONDS);
        }

        void resumeSave() {
            SavePause pause = nextSave.get();
            if (pause != null) {
                pause.resume().countDown();
            }
        }

        @Override
        public void save(OAuth2Authorization authorization) {
            SavePause pause = nextSave.get();
            if (pause != null) {
                pause.entered().countDown();
                try {
                    if (!pause.resume().await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("等待测试放行授权保存超时");
                    }
                }
                catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("等待测试放行授权保存时被中断", ex);
                }
                finally {
                    nextSave.compareAndSet(pause, null);
                }
            }
            delegate.save(authorization);
        }

        @Override
        public void remove(OAuth2Authorization authorization) {
            delegate.remove(authorization);
        }

        @Override
        public OAuth2Authorization findById(String id) {
            return delegate.findById(id);
        }

        @Override
        public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
            return delegate.findByToken(token, tokenType);
        }
    }

    private record SavePause(CountDownLatch entered, CountDownLatch resume) {

        private SavePause() {
            this(new CountDownLatch(1), new CountDownLatch(1));
        }
    }
}
