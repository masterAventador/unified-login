package com.aventador.unifiedlogin.security;

import com.aventador.unifiedlogin.support.MutableTicker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class LoginAttemptServiceTest {

    private static final Duration LOCK_DURATION = Duration.ofMinutes(15);

    private MutableTicker ticker;
    private LoginAttemptService service;

    @BeforeEach
    void setUp() {
        ticker = new MutableTicker();
        service = new LoginAttemptService(new LoginRateLimitProperties(5, LOCK_DURATION, 20), ticker);
    }

    @Test
    void doesNotLockBeforeReachingThreshold() {
        for (int i = 0; i < 4; i++) {
            service.recordFailure("user@example.com");
        }

        assertThat(service.isLocked("user@example.com")).isFalse();
    }

    @Test
    void locksOnceThresholdReached() {
        for (int i = 0; i < 5; i++) {
            service.recordFailure("user@example.com");
        }

        assertThat(service.isLocked("user@example.com")).isTrue();
    }

    @Test
    void countsFailuresIgnoringEmailCaseAndSurroundingSpace() {
        service.recordFailure("User@Example.com");
        service.recordFailure("user@example.COM");
        service.recordFailure("  USER@EXAMPLE.COM  ");
        service.recordFailure("user@example.com");
        service.recordFailure("uSeR@eXaMpLe.CoM");

        assertThat(service.isLocked("user@example.com")).isTrue();
    }

    @Test
    void locksMalformedEmailToo() {
        // 防枚举：对格式非法的输入也要计数，否则「会不会被锁」本身就泄漏了账号是否存在
        for (int i = 0; i < 5; i++) {
            service.recordFailure("not-an-email");
        }

        assertThat(service.isLocked("not-an-email")).isTrue();
    }

    @Test
    void unlocksAfterLockDurationElapses() {
        for (int i = 0; i < 5; i++) {
            service.recordFailure("user@example.com");
        }
        assertThat(service.isLocked("user@example.com")).isTrue();

        ticker.advance(LOCK_DURATION.plusSeconds(1));

        assertThat(service.isLocked("user@example.com")).isFalse();
    }

    @Test
    void keepsLockedUntilLockDurationElapses() {
        for (int i = 0; i < 5; i++) {
            service.recordFailure("user@example.com");
        }

        ticker.advance(LOCK_DURATION.minusSeconds(1));

        assertThat(service.isLocked("user@example.com")).isTrue();
    }

    @Test
    void keepsCountingWhenFailuresAreSpacedJustInsideTheWindow() {
        // 计数窗口随每次失败顺延：只要相邻两次失败没隔满锁定时长，慢慢试也会累计到阈值
        for (int i = 0; i < 4; i++) {
            service.recordFailure("user@example.com");
            ticker.advance(LOCK_DURATION.minusSeconds(1));
        }
        service.recordFailure("user@example.com");

        assertThat(service.isLocked("user@example.com")).isTrue();
    }

    @Test
    void forgetsEarlierFailuresOnceTheGapExceedsTheWindow() {
        for (int i = 0; i < 4; i++) {
            service.recordFailure("user@example.com");
        }

        ticker.advance(LOCK_DURATION.plusSeconds(1));
        service.recordFailure("user@example.com");

        assertThat(service.isLocked("user@example.com")).isFalse();
    }

    @Test
    void successfulLoginClearsFailureCount() {
        for (int i = 0; i < 4; i++) {
            service.recordFailure("user@example.com");
        }

        service.clearFailures("user@example.com");
        service.recordFailure("user@example.com");

        assertThat(service.isLocked("user@example.com")).isFalse();
    }

    @Test
    void allowsAttemptsUpToIpLimit() {
        boolean exceeded = false;
        for (int i = 0; i < 20; i++) {
            exceeded = service.registerAttemptAndCheckRateLimit("10.0.0.1");
        }

        assertThat(exceeded).isFalse();
    }

    @Test
    void flagsAttemptBeyondIpLimit() {
        for (int i = 0; i < 20; i++) {
            service.registerAttemptAndCheckRateLimit("10.0.0.1");
        }

        assertThat(service.registerAttemptAndCheckRateLimit("10.0.0.1")).isTrue();
    }

    @Test
    void tracksIpLimitsIndependentlyPerAddress() {
        for (int i = 0; i < 21; i++) {
            service.registerAttemptAndCheckRateLimit("10.0.0.1");
        }

        assertThat(service.registerAttemptAndCheckRateLimit("10.0.0.2")).isFalse();
    }

    @Test
    void resetsIpWindowAfterOneMinute() {
        for (int i = 0; i < 21; i++) {
            service.registerAttemptAndCheckRateLimit("10.0.0.1");
        }

        ticker.advance(Duration.ofMinutes(1).plusSeconds(1));

        assertThat(service.registerAttemptAndCheckRateLimit("10.0.0.1")).isFalse();
    }

    @Test
    void windowStartsAtFirstAttemptSoSustainedTrafficStillRecovers() {
        // 窗口从第一次尝试起算，不因后续尝试而顺延；否则持续敲门的 NAT 出口 IP
        // 一旦超限就再也恢复不了，把限流变成了永久封禁
        service.registerAttemptAndCheckRateLimit("10.0.0.1");
        for (int i = 0; i < 30; i++) {
            ticker.advance(Duration.ofSeconds(2));
            service.registerAttemptAndCheckRateLimit("10.0.0.1");
        }

        assertThat(service.registerAttemptAndCheckRateLimit("10.0.0.1")).isFalse();
    }

    @Test
    void clearsFailuresIgnoringEmailCase() {
        for (int i = 0; i < 4; i++) {
            service.recordFailure("user@example.com");
        }

        // 登录成功事件回传的主体名可能与用户输入的大小写不同，清零必须走同一套归一化
        service.clearFailures("USER@Example.com");
        service.recordFailure("user@example.com");

        assertThat(service.isLocked("user@example.com")).isFalse();
    }
}
