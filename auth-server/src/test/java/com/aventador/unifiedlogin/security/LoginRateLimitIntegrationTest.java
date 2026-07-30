package com.aventador.unifiedlogin.security;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.MutableTicker;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class LoginRateLimitIntegrationTest {

    private static final String PASSWORD = "a valid password";
    private static final String WRONG_PASSWORD = "wrong password";
    private static final String LOCKED_URL = "/login?locked";
    private static final String ERROR_URL = "/login?error";
    private static final Duration LOCK_DURATION = Duration.ofMinutes(15);

    /** 登录页锁定提示的稳定标记。断在 data-testid 上而非提示文案上，改文案不会误伤这条用例。 */
    private static final String LOCKED_NOTICE_MARKER = "data-testid=\"login-locked\"";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private LoginAttemptService loginAttemptService;

    // 计数在每个测试方法前由 LoginAttemptResetTestExecutionListener 统一清零，
    // 否则同一个类里靠前的用例消耗掉的尝试次数会把靠后的用例顶过 IP 上限
    @Autowired
    private MutableTicker ticker;

    @Test
    void locksAccountAfterFiveFailuresEvenWithCorrectPassword() throws Exception {
        String email = "lockout@example.com";
        register(email);

        failFiveTimes(email);

        // 真实终态：第六次密码完全正确也进不去
        mockMvc.perform(formLogin("/login").user(email).password(PASSWORD))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl(LOCKED_URL));
    }

    @Test
    void allowsLoginWhileFailuresStayBelowThreshold() throws Exception {
        String email = "under-threshold@example.com";
        register(email);

        for (int i = 0; i < 4; i++) {
            mockMvc.perform(formLogin("/login").user(email).password(WRONG_PASSWORD))
                    .andExpect(unauthenticated())
                    .andExpect(redirectedUrl(ERROR_URL));
        }

        // 第五次用正确密码：还没到阈值，必须能正常登录，限流不得误伤
        mockMvc.perform(formLogin("/login").user(email).password(PASSWORD))
                .andExpect(authenticated());
    }

    @Test
    void locksUnknownEmailToo() throws Exception {
        // 防枚举：不存在的邮箱如果永远不会被锁，攻击者只要看会不会锁就知道账号在不在
        String email = "ghost-lockout@example.com";

        failFiveTimes(email);

        mockMvc.perform(formLogin("/login").user(email).password(PASSWORD))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl(LOCKED_URL));
    }

    @Test
    void locksDisabledAccountToo() throws Exception {
        // 防枚举：禁用账号走的是 DisabledException 而非 BadCredentialsException，
        // 若这条分支不计数，攻击者只要看第六次是 ?locked 还是 ?error 就能认出「真实存在且已禁用」的账号
        String email = "disabled-lockout@example.com";
        register(email);
        jdbcTemplate.update("UPDATE app_user SET status = 'DISABLED' WHERE email = ?", email);

        failFiveTimes(email);

        mockMvc.perform(formLogin("/login").user(email).password(PASSWORD))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl(LOCKED_URL));
    }

    @Test
    void badBearerTokensDoNotPolluteTheEmailFailureCounter() throws Exception {
        // 资源服务器的坏 token 失败也会映射成 BadCredentials 事件，若照单计数，
        // 键就是 token 字符串本身。攻击者刷满一万个随机 token 即可按大小淘汰
        // 把某个真实邮箱已生效的锁定记录挤出缓存，锁定随之消失——一条锁定绕过路径
        String badToken = "definitely-not-a-jwt";

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(get("/userinfo")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + badToken)
                            .accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isUnauthorized());
        }

        assertThat(loginAttemptService.isLocked(badToken)).isFalse();
    }

    @Test
    void locksMalformedEmailToo() throws Exception {
        // 同上：格式非法的输入若不计数，「有没有被锁」同样能区分出输入是否落在真实账号空间
        String malformed = "not-an-email";

        failFiveTimes(malformed);

        mockMvc.perform(formLogin("/login").user(malformed).password(PASSWORD))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl(LOCKED_URL));
    }

    @Test
    void unlocksAfterLockDurationSoOwnerGetsBackIn() throws Exception {
        String email = "lock-expiry@example.com";
        register(email);
        failFiveTimes(email);
        mockMvc.perform(formLogin("/login").user(email).password(PASSWORD))
                .andExpect(redirectedUrl(LOCKED_URL));

        ticker.advance(LOCK_DURATION.plusSeconds(1));

        // 真实终态：锁定期满，账号主人拿正确密码能重新登进来
        mockMvc.perform(formLogin("/login").user(email).password(PASSWORD))
                .andExpect(authenticated());
    }

    @Test
    void staysLockedUntilLockDurationElapses() throws Exception {
        String email = "still-locked@example.com";
        register(email);
        failFiveTimes(email);

        ticker.advance(LOCK_DURATION.minusSeconds(1));

        mockMvc.perform(formLogin("/login").user(email).password(PASSWORD))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl(LOCKED_URL));
    }

    @Test
    void successfulLoginResetsFailureCount() throws Exception {
        String email = "reset-count@example.com";
        register(email);

        for (int i = 0; i < 4; i++) {
            mockMvc.perform(formLogin("/login").user(email).password(WRONG_PASSWORD))
                    .andExpect(unauthenticated());
        }

        mockMvc.perform(formLogin("/login").user(email).password(PASSWORD))
                .andExpect(authenticated());

        // 计数已清零，再错四次仍不该锁，第五次正确密码依旧能登入
        for (int i = 0; i < 4; i++) {
            mockMvc.perform(formLogin("/login").user(email).password(WRONG_PASSWORD))
                    .andExpect(unauthenticated());
        }

        mockMvc.perform(formLogin("/login").user(email).password(PASSWORD))
                .andExpect(authenticated());
    }

    @Test
    void rejectsWithTooManyRequestsBeyondIpLimit() throws Exception {
        // 每次换一个邮箱，避免先撞上账号锁定，从而单独验证 IP 维度
        for (int i = 0; i < 20; i++) {
            mockMvc.perform(formLogin("/login").user("ip-" + i + "@example.com").password(PASSWORD))
                    .andExpect(status().isFound());
        }

        mockMvc.perform(formLogin("/login").user("ip-last@example.com").password(PASSWORD))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void allowsLoginAgainAfterIpWindowElapses() throws Exception {
        String email = "ip-window@example.com";
        register(email);
        for (int i = 0; i < 21; i++) {
            mockMvc.perform(formLogin("/login").user("ip-window-" + i + "@example.com").password(PASSWORD));
        }

        ticker.advance(Duration.ofMinutes(1).plusSeconds(1));

        // 真实终态：窗口过去后同一地址的正常用户能重新登录
        mockMvc.perform(formLogin("/login").user(email).password(PASSWORD))
                .andExpect(authenticated());
    }

    @Test
    void loginPageShowsLockedNotice() throws Exception {
        String email = "notice@example.com";
        register(email);
        failFiveTimes(email);
        mockMvc.perform(formLogin("/login").user(email).password(PASSWORD))
                .andExpect(redirectedUrl(LOCKED_URL));

        // 跟着跳转地址走一遍，确认用户真的看得到锁定提示，而不只是 URL 上多了个参数；
        // 文案里的分钟数必须与本环境配置的 15m 一致，配套的 LoginLockNoticeDurationTest 用另一份配置验证它确实跟着配置走
        mockMvc.perform(get("/login").param("locked", ""))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(LOCKED_NOTICE_MARKER)))
                .andExpect(content().string(containsString(LOCK_DURATION.toMinutes() + " 分钟")));
    }

    @Test
    void loginPageHidesLockedNoticeWithoutTheParameter() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString(LOCKED_NOTICE_MARKER))));
    }

    private void register(String email) {
        registrationService.register(email, PASSWORD);
    }

    private void failFiveTimes(String email) throws Exception {
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(formLogin("/login").user(email).password(WRONG_PASSWORD))
                    .andExpect(unauthenticated())
                    .andExpect(redirectedUrl(ERROR_URL));
        }
    }
}
