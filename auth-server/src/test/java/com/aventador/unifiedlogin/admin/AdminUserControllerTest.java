package com.aventador.unifiedlogin.admin;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import com.aventador.unifiedlogin.user.AppUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class AdminUserControllerTest {

    private static final String PASSWORD = "a valid password";

    private static final String NEW_PASSWORD = "a newer valid password";

    private static final String ADMIN_CLIENT_ID = "admin-web";

    private static final String ADMIN_REDIRECT_URI = "http://localhost:5175/callback";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Test
    void listsUsersWithPaginationEmailSearchAndStatusFilterWithoutPasswordHash() throws Exception {
        String marker = "admin-list-" + UUID.randomUUID();
        AdminIdentity admin = createAdmin(marker + "-operator@example.com");
        registrationService.register(marker + "-active@example.com", PASSWORD);
        AppUser disabled = registrationService.register(marker + "-disabled@example.com", PASSWORD);
        assertThat(jdbcTemplate.update(
                "UPDATE app_user SET status = 'DISABLED' WHERE id = ?", disabled.getId()))
                .isEqualTo(1);

        String response = mockMvc.perform(get("/admin/users")
                        .header("Authorization", bearer(admin.accessToken()))
                        .queryParam("page", "0")
                        .queryParam("size", "1")
                        .queryParam("email", marker)
                        .queryParam("status", "DISABLED")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].id").value(disabled.getId().toString()))
                .andExpect(jsonPath("$.content[0].email").value(disabled.getEmail()))
                .andExpect(jsonPath("$.content[0].status").value("DISABLED"))
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(1))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andReturn()
                .getResponse()
                .getContentAsString(StandardCharsets.UTF_8);

        assertThat(response)
                .doesNotContain("passwordHash")
                .doesNotContain("password_hash")
                .doesNotContain(disabled.getPasswordHash());
    }

    @Test
    void treatsLikeMetacharactersInEmailSearchAsLiteralText() throws Exception {
        String marker = "admin-literal-" + UUID.randomUUID();
        AdminIdentity admin = createAdmin(marker + "-operator@example.com");
        AppUser underscore = registrationService.register(
                marker + "-literal_a@example.com", PASSWORD);
        registrationService.register(marker + "-literalxa@example.com", PASSWORD);
        AppUser percent = registrationService.register(
                marker + "-percent%value@example.com", PASSWORD);
        registrationService.register(marker + "-percentxxvalue@example.com", PASSWORD);
        AppUser escapeCharacter = registrationService.register(
                marker + "-bang!value@example.com", PASSWORD);

        mockMvc.perform(get("/admin/users")
                        .header("Authorization", bearer(admin.accessToken()))
                        .queryParam("email", marker + "-literal_a")
                        .queryParam("status", "ACTIVE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].id").value(underscore.getId().toString()))
                .andExpect(jsonPath("$.totalElements").value(1));

        mockMvc.perform(get("/admin/users")
                        .header("Authorization", bearer(admin.accessToken()))
                        .queryParam("email", marker + "-percent%value")
                        .queryParam("status", "ACTIVE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].id").value(percent.getId().toString()))
                .andExpect(jsonPath("$.totalElements").value(1));

        mockMvc.perform(get("/admin/users")
                        .header("Authorization", bearer(admin.accessToken()))
                        .queryParam("email", marker + "-bang!value")
                        .queryParam("status", "ACTIVE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].id").value(escapeCharacter.getId().toString()))
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    @Test
    void disablesUserAndImmediatelyRejectsLoginAndExistingRefreshToken() throws Exception {
        String marker = "admin-disable-" + UUID.randomUUID();
        AdminIdentity admin = createAdmin(marker + "-operator@example.com");
        AppUser target = registrationService.register(marker + "-target@example.com", PASSWORD);
        IssuedTokens targetTokens = issueTokens(target.getEmail(), PASSWORD);

        mockMvc.perform(post("/admin/users/{id}/disable", target.getId())
                        .header("Authorization", bearer(admin.accessToken())))
                .andExpect(status().isNoContent());

        mockMvc.perform(formLogin("/login").user(target.getEmail()).password(PASSWORD))
                .andExpect(unauthenticated());
        assertRefreshRejected(targetTokens.refreshToken());

        mockMvc.perform(post("/admin/users/{id}/enable", target.getId())
                        .header("Authorization", bearer(admin.accessToken())))
                .andExpect(status().isNoContent());
        assertRefreshRejected(targetTokens.refreshToken());
    }

    @Test
    void enablesDisabledUser() throws Exception {
        String marker = "admin-enable-" + UUID.randomUUID();
        AdminIdentity admin = createAdmin(marker + "-operator@example.com");
        AppUser target = registrationService.register(marker + "-target@example.com", PASSWORD);
        assertThat(jdbcTemplate.update(
                "UPDATE app_user SET status = 'DISABLED' WHERE id = ?", target.getId()))
                .isEqualTo(1);

        mockMvc.perform(post("/admin/users/{id}/enable", target.getId())
                        .header("Authorization", bearer(admin.accessToken())))
                .andExpect(status().isNoContent());

        mockMvc.perform(formLogin("/login").user(target.getEmail()).password(PASSWORD))
                .andExpect(authenticated());
    }

    @Test
    void resetsPasswordAndImmediatelyRejectsOldPasswordAndExistingRefreshToken() throws Exception {
        String marker = "admin-reset-" + UUID.randomUUID();
        AdminIdentity admin = createAdmin(marker + "-operator@example.com");
        AppUser target = registrationService.register(marker + "-target@example.com", PASSWORD);
        IssuedTokens targetTokens = issueTokens(target.getEmail(), PASSWORD);

        mockMvc.perform(post("/admin/users/{id}/reset-password", target.getId())
                        .header("Authorization", bearer(admin.accessToken()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"newPassword":"%s"}
                                """.formatted(NEW_PASSWORD)))
                .andExpect(status().isNoContent());

        mockMvc.perform(formLogin("/login").user(target.getEmail()).password(PASSWORD))
                .andExpect(unauthenticated());
        mockMvc.perform(formLogin("/login").user(target.getEmail()).password(NEW_PASSWORD))
                .andExpect(authenticated());
        assertRefreshRejected(targetTokens.refreshToken());
    }

    @Test
    void rejectsWeakResetPasswordWithoutChangingPasswordOrRevokingTokens() throws Exception {
        String marker = "admin-weak-reset-" + UUID.randomUUID();
        AdminIdentity admin = createAdmin(marker + "-operator@example.com");
        AppUser target = registrationService.register(marker + "-target@example.com", PASSWORD);
        IssuedTokens targetTokens = issueTokens(target.getEmail(), PASSWORD);

        mockMvc.perform(post("/admin/users/{id}/reset-password", target.getId())
                        .header("Authorization", bearer(admin.accessToken()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"newPassword":"short"}
                                """))
                .andExpect(status().isBadRequest());

        mockMvc.perform(formLogin("/login").user(target.getEmail()).password(PASSWORD))
                .andExpect(authenticated());
        assertThat(OAuth2TestFlows.jsonField(
                OAuth2TestFlows.refreshTokens(mockMvc, targetTokens.refreshToken()), "access_token"))
                .isNotBlank();
    }

    @Test
    void administratorCannotDisableSelf() throws Exception {
        String marker = "admin-self-disable-" + UUID.randomUUID();
        AdminIdentity admin = createAdmin(marker + "-operator@example.com");

        mockMvc.perform(post("/admin/users/{id}/disable", admin.userId())
                        .header("Authorization", bearer(admin.accessToken())))
                .andExpect(status().isConflict());

        mockMvc.perform(get("/admin/users")
                        .header("Authorization", bearer(admin.accessToken()))
                        .queryParam("email", marker))
                .andExpect(status().isOk());
        assertThat(jdbcTemplate.queryForObject(
                "SELECT status FROM app_user WHERE id = ?", String.class, admin.userId()))
                .isEqualTo("ACTIVE");
    }

    @Test
    void disabledPlatformAdministratorCannotUseOldAccessTokenToReenableSelf() throws Exception {
        String marker = "admin-disabled-operator-" + UUID.randomUUID();
        AdminIdentity activeAdmin = createAdmin(marker + "-active@example.com");
        AdminIdentity disabledAdmin = createAdmin(marker + "-disabled@example.com");

        mockMvc.perform(post("/admin/users/{id}/disable", disabledAdmin.userId())
                        .header("Authorization", bearer(activeAdmin.accessToken())))
                .andExpect(status().isNoContent());

        mockMvc.perform(post("/admin/users/{id}/enable", disabledAdmin.userId())
                        .header("Authorization", bearer(disabledAdmin.accessToken())))
                .andExpect(status().isForbidden());
        assertThat(jdbcTemplate.queryForObject(
                "SELECT status FROM app_user WHERE id = ?", String.class, disabledAdmin.userId()))
                .isEqualTo("DISABLED");
    }

    @Test
    void administratorDisabledAfterGuardCheckCannotWinRaceToReenableSelf() throws Exception {
        String marker = "admin-disable-race-" + UUID.randomUUID();
        AdminIdentity admin = createAdmin(marker + "@example.com");
        CountDownLatch disableUpdated = new CountDownLatch(1);
        CountDownLatch allowDisableCommit = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);

        try {
            Future<?> disableTransaction = executor.submit(() -> {
                new TransactionTemplate(transactionManager).executeWithoutResult((status) -> {
                    assertThat(jdbcTemplate.update(
                            "UPDATE app_user SET status = 'DISABLED' WHERE id = ?", admin.userId()))
                            .isEqualTo(1);
                    disableUpdated.countDown();
                    awaitLatch(allowDisableCommit, "等待放行禁用事务提交");
                });
                return null;
            });
            awaitLatch(disableUpdated, "禁用事务应先写入未提交状态");

            Future<Integer> reenableStatus = executor.submit(() ->
                    mockMvc.perform(post("/admin/users/{id}/enable", admin.userId())
                                    .header("Authorization", bearer(admin.accessToken())))
                            .andReturn()
                            .getResponse()
                            .getStatus());

            try {
                assertThatExceptionOfType(TimeoutException.class)
                        .as("启用请求应已通过 Guard，并等待禁用事务持有的用户行锁")
                        .isThrownBy(() -> reenableStatus.get(1, TimeUnit.SECONDS));
            }
            finally {
                allowDisableCommit.countDown();
            }

            disableTransaction.get(10, TimeUnit.SECONDS);
            assertThat(reenableStatus.get(10, TimeUnit.SECONDS)).isEqualTo(403);
            assertThat(jdbcTemplate.queryForObject(
                    "SELECT status FROM app_user WHERE id = ?", String.class, admin.userId()))
                    .isEqualTo("DISABLED");
        }
        finally {
            allowDisableCommit.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void administratorDisabledAfterGuardCheckCannotWinRaceToDisableAnotherUser() throws Exception {
        String marker = "admin-disable-target-race-" + UUID.randomUUID();
        AdminIdentity admin = createAdmin(marker + "-operator@example.com");
        AppUser target = registrationService.register(marker + "-target@example.com", PASSWORD);
        CountDownLatch revocationLocked = new CountDownLatch(1);
        CountDownLatch allowRevocationCommit = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);

        try {
            Future<?> revocationTransaction = executor.submit(() -> {
                new TransactionTemplate(transactionManager).executeWithoutResult((status) -> {
                    assertThat(jdbcTemplate.update(
                            "UPDATE app_user SET status = 'DISABLED' WHERE id = ?", admin.userId()))
                            .isEqualTo(1);
                    assertThat(jdbcTemplate.queryForObject(
                            "SELECT id FROM app_user WHERE id = ? FOR UPDATE",
                            UUID.class,
                            target.getId()))
                            .isEqualTo(target.getId());
                    revocationLocked.countDown();
                    awaitLatch(allowRevocationCommit, "等待放行管理员权限撤销事务提交");
                });
                return null;
            });
            awaitLatch(revocationLocked, "权限撤销事务应先锁定管理员与目标用户");

            Future<Integer> disableStatus = executor.submit(() ->
                    mockMvc.perform(post("/admin/users/{id}/disable", target.getId())
                                    .header("Authorization", bearer(admin.accessToken())))
                            .andReturn()
                            .getResponse()
                            .getStatus());

            try {
                assertThatExceptionOfType(TimeoutException.class)
                        .as("禁用请求应已通过 Guard，并等待权限撤销事务持有的用户行锁")
                        .isThrownBy(() -> disableStatus.get(1, TimeUnit.SECONDS));
            }
            finally {
                allowRevocationCommit.countDown();
            }

            revocationTransaction.get(10, TimeUnit.SECONDS);
            assertThat(disableStatus.get(10, TimeUnit.SECONDS)).isEqualTo(403);
            assertThat(jdbcTemplate.queryForObject(
                    "SELECT status FROM app_user WHERE id = ?", String.class, target.getId()))
                    .isEqualTo("ACTIVE");
        }
        finally {
            allowRevocationCommit.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void administratorDisabledAfterGuardCheckCannotWinRaceToResetAnotherPassword() throws Exception {
        String marker = "admin-reset-target-race-" + UUID.randomUUID();
        AdminIdentity admin = createAdmin(marker + "-operator@example.com");
        AppUser target = registrationService.register(marker + "-target@example.com", PASSWORD);
        CountDownLatch revocationLocked = new CountDownLatch(1);
        CountDownLatch allowRevocationCommit = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);

        try {
            Future<?> revocationTransaction = executor.submit(() -> {
                new TransactionTemplate(transactionManager).executeWithoutResult((status) -> {
                    assertThat(jdbcTemplate.update(
                            "UPDATE app_user SET status = 'DISABLED' WHERE id = ?", admin.userId()))
                            .isEqualTo(1);
                    assertThat(jdbcTemplate.queryForObject(
                            "SELECT id FROM app_user WHERE id = ? FOR UPDATE",
                            UUID.class,
                            target.getId()))
                            .isEqualTo(target.getId());
                    revocationLocked.countDown();
                    awaitLatch(allowRevocationCommit, "等待放行管理员权限撤销事务提交");
                });
                return null;
            });
            awaitLatch(revocationLocked, "权限撤销事务应先锁定管理员与目标用户");

            Future<Integer> resetStatus = executor.submit(() ->
                    mockMvc.perform(post("/admin/users/{id}/reset-password", target.getId())
                                    .header("Authorization", bearer(admin.accessToken()))
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content("""
                                            {"newPassword":"%s"}
                                            """.formatted(NEW_PASSWORD)))
                            .andReturn()
                            .getResponse()
                            .getStatus());

            try {
                assertThatExceptionOfType(TimeoutException.class)
                        .as("重置请求应已通过 Guard，并等待权限撤销事务持有的用户行锁")
                        .isThrownBy(() -> resetStatus.get(1, TimeUnit.SECONDS));
            }
            finally {
                allowRevocationCommit.countDown();
            }

            revocationTransaction.get(10, TimeUnit.SECONDS);
            assertThat(resetStatus.get(10, TimeUnit.SECONDS)).isEqualTo(403);
            mockMvc.perform(formLogin("/login").user(target.getEmail()).password(PASSWORD))
                    .andExpect(authenticated());
            mockMvc.perform(formLogin("/login").user(target.getEmail()).password(NEW_PASSWORD))
                    .andExpect(unauthenticated());
        }
        finally {
            allowRevocationCommit.countDown();
            executor.shutdownNow();
        }
    }

    private AdminIdentity createAdmin(String email) throws Exception {
        AppUser user = registrationService.register(email, PASSWORD);
        assertThat(jdbcTemplate.update(
                "UPDATE app_user SET is_platform_admin = true WHERE id = ?", user.getId()))
                .isEqualTo(1);
        return new AdminIdentity(user.getId(),
                issueTokens(email, PASSWORD, ADMIN_CLIENT_ID, ADMIN_REDIRECT_URI).accessToken());
    }

    private IssuedTokens issueTokens(String email, String password) throws Exception {
        return issueTokens(email, password, OAuth2TestFlows.CLIENT_ID, OAuth2TestFlows.REDIRECT_URI);
    }

    private IssuedTokens issueTokens(
            String email,
            String password,
            String clientId,
            String redirectUri)
            throws Exception {
        MockHttpSession session = OAuth2TestFlows.login(mockMvc, email, password);
        String response = OAuth2TestFlows.exchangeCode(
                mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc, session, clientId, redirectUri),
                clientId,
                redirectUri);
        return new IssuedTokens(
                OAuth2TestFlows.jsonField(response, "access_token"),
                OAuth2TestFlows.jsonField(response, "refresh_token"));
    }

    private void assertRefreshRejected(String refreshToken) throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", OAuth2TestFlows.CLIENT_ID)
                        .param("refresh_token", refreshToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.refresh_token").doesNotExist());
    }

    private String bearer(String accessToken) {
        return "Bearer " + accessToken;
    }

    private void awaitLatch(CountDownLatch latch, String description) {
        try {
            assertThat(latch.await(10, TimeUnit.SECONDS)).as(description).isTrue();
        }
        catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(description + "时被中断", ex);
        }
    }

    private record AdminIdentity(UUID userId, String accessToken) {
    }

    private record IssuedTokens(String accessToken, String refreshToken) {
    }
}
