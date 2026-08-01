package com.aventador.unifiedlogin.account;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import com.aventador.unifiedlogin.user.AppUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 撤销与刷新不能只在顺序调用时正确：刷新 provider 会先读授权、后保存轮转结果，
 * 如果撤销恰好落在两者之间，未经串行化的 JDBC service 会把刚删掉的授权重新 INSERT。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import({PostgresTestConfig.class, TokenRevocationConcurrencyTest.PausingAuthorizationConfig.class})
class TokenRevocationConcurrencyTest {

    private static final String PASSWORD = "a valid password";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private TokenRevocationService tokenRevocationService;

    @Autowired
    private PausingAuthorizationService authorizationService;

    @Test
    void revocationCannotBeOvertakenByAnAlreadyInFlightRefresh() throws Exception {
        IssuedTokens target = issueTokens("concurrent-revoke@example.com");
        authorizationService.pauseNextSave();

        AtomicReference<String> refreshResponse = new AtomicReference<>();
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> refresh = executor.submit(() -> {
                refreshResponse.set(OAuth2TestFlows.refreshTokens(mockMvc, target.refreshToken()));
                return null;
            });
            assertThat(authorizationService.awaitPausedSave())
                    .as("刷新请求应停在持久化轮转结果之前")
                    .isTrue();

            Future<?> revocation = executor.submit(
                    () -> tokenRevocationService.revokeAllTokensOf(target.userId()));

            boolean revocationFinishedBeforeRefreshSave;
            try {
                revocation.get(2, TimeUnit.SECONDS);
                revocationFinishedBeforeRefreshSave = true;
            }
            catch (TimeoutException expectedWhenSerialized) {
                revocationFinishedBeforeRefreshSave = false;
            }
            finally {
                authorizationService.resumeSave();
            }

            refresh.get(10, TimeUnit.SECONDS);
            revocation.get(10, TimeUnit.SECONDS);

            assertThat(revocationFinishedBeforeRefreshSave)
                    .as("撤销必须等待已在途的刷新完成，随后删除其新授权")
                    .isFalse();
        }
        finally {
            authorizationService.resumeSave();
            executor.shutdownNow();
        }

        String rotatedRefreshToken = OAuth2TestFlows.jsonField(
                refreshResponse.get(), "refresh_token");
        assertRefreshIssuesNothing(rotatedRefreshToken);
    }

    @Test
    void concurrentSecondUseStillRevokesEverySession() throws Exception {
        IssuedTokens target = issueTokens("concurrent-replay@example.com");
        String secondSessionRefreshToken = issueAdditionalRefreshToken("concurrent-replay@example.com");
        authorizationService.pauseNextSave();

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<String> firstUse = executor.submit(
                    () -> OAuth2TestFlows.refreshTokens(mockMvc, target.refreshToken()));
            assertThat(authorizationService.awaitPausedSave())
                    .as("首次刷新应停在持久化轮转结果之前")
                    .isTrue();

            Future<Integer> secondUse = executor.submit(() -> mockMvc.perform(post("/oauth2/token")
                            .param("grant_type", "refresh_token")
                            .param("client_id", OAuth2TestFlows.CLIENT_ID)
                            .param("refresh_token", target.refreshToken()))
                    .andReturn()
                    .getResponse()
                    .getStatus());

            boolean replayFinishedBeforeFirstUseCommitted;
            try {
                secondUse.get(2, TimeUnit.SECONDS);
                replayFinishedBeforeFirstUseCommitted = true;
            }
            catch (TimeoutException expectedWhenSerialized) {
                replayFinishedBeforeFirstUseCommitted = false;
            }
            finally {
                authorizationService.resumeSave();
            }

            String rotatedRefreshToken = OAuth2TestFlows.jsonField(
                    firstUse.get(10, TimeUnit.SECONDS), "refresh_token");
            assertThat(secondUse.get(10, TimeUnit.SECONDS)).isBetween(400, 499);
            assertThat(replayFinishedBeforeFirstUseCommitted)
                    .as("并发的第二次提交必须等待首次轮转提交，随后识别为重放")
                    .isFalse();

            assertRefreshIssuesNothing(rotatedRefreshToken);
            assertRefreshIssuesNothing(secondSessionRefreshToken);
        }
        finally {
            authorizationService.resumeSave();
            executor.shutdownNow();
        }
    }

    private IssuedTokens issueTokens(String email) throws Exception {
        AppUser user = registrationService.register(email, PASSWORD);
        return new IssuedTokens(user.getId(), issueAdditionalRefreshToken(email));
    }

    private String issueAdditionalRefreshToken(String email) throws Exception {
        MockHttpSession session = OAuth2TestFlows.login(mockMvc, email, PASSWORD);
        String response = OAuth2TestFlows.exchangeCode(
                mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc, session));
        return OAuth2TestFlows.jsonField(response, "refresh_token");
    }

    private void assertRefreshIssuesNothing(String refreshToken) throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", OAuth2TestFlows.CLIENT_ID)
                        .param("refresh_token", refreshToken))
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andExpect(jsonPath("$.id_token").doesNotExist());
    }

    private record IssuedTokens(UUID userId, String refreshToken) {
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class PausingAuthorizationConfig {

        @Bean
        @Primary
        PausingAuthorizationService pausingAuthorizationService(
                JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
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
            assertThat(nextSave.compareAndSet(null, new SavePause()))
                    .as("同一时刻只能暂停一次授权保存")
                    .isTrue();
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
