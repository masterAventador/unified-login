package com.aventador.unifiedlogin.security;

import com.aventador.unifiedlogin.user.EmailAddress;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.github.benmanes.caffeine.cache.Ticker;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * 登录尝试的计数与判定。
 *
 * <p><b>已知限制</b>：计数保存在应用内存中，只适用于单实例部署。多实例部署时每个实例各记各的，
 * 攻击者轮换实例即可放大到 N 倍尝试次数。改共享存储是后续阶段的事，本阶段作为已登记的取舍。
 */
@Service
public class LoginAttemptService {

    private static final Duration IP_WINDOW = Duration.ofMinutes(1);

    /**
     * 单张计数表的容量上限。没有上限时任何人都能靠伪造大量邮箱把内存打满，
     * 代价是撑满以后最早的计数会被挤掉、对应的锁定提前失效——这里选择先保住可用性。
     * 两张表合计最坏约占几 MB（每条记录是一个字符串键加一个装箱计数，含 Caffeine 节点开销）。
     */
    private static final int MAX_TRACKED_KEYS = 10_000;

    private final LoginRateLimitProperties properties;
    private final Cache<String, Integer> failuresByEmail;
    private final Cache<String, Integer> attemptsByIp;

    public LoginAttemptService(LoginRateLimitProperties properties, Ticker ticker) {
        this.properties = properties;
        // expireAfterWrite 的含义是「距最后一次写入」，因此这里有两层效果：
        // 一是锁定期从最后一次失败起算——被锁期间的尝试不再计数（见 LoginRateLimitFilter），
        // 最后一次写入就是触发锁定的那一次，锁定时长正好等于配置值；
        // 二是失败计数的累计窗口也随每次失败顺延，只要相邻两次失败间隔不超过配置时长，
        // 哪怕跨几个小时慢慢试满五次也会锁定。方向上偏保守，宁可多锁不可漏锁。
        this.failuresByEmail = Caffeine.newBuilder()
                .expireAfterWrite(properties.emailLockDuration())
                .maximumSize(MAX_TRACKED_KEYS)
                .ticker(ticker)
                .build();
        // 用 expireAfterCreate 而不是 expireAfterWrite：窗口必须从本窗口第一次尝试起算。
        // 若每次尝试都顺延窗口，持续敲门的 IP 将永远无法恢复，共用出口 IP 的正常用户会被无限期挡住
        this.attemptsByIp = Caffeine.newBuilder()
                .expireAfter(Expiry.creating((String ip, Integer attempts) -> IP_WINDOW))
                .maximumSize(MAX_TRACKED_KEYS)
                .ticker(ticker)
                .build();
    }

    /**
     * 用 {@link EmailAddress#normalize} 而不是 {@code new EmailAddress(...)}：后者遇到非法格式会抛异常，
     * 那样格式非法的输入就不会被计数，攻击者据此即可区分「格式合法但不存在」与「格式非法」。
     */
    public void recordFailure(String email) {
        failuresByEmail.asMap().merge(EmailAddress.normalize(email), 1, Integer::sum);
    }

    public boolean isLocked(String email) {
        Integer failures = failuresByEmail.getIfPresent(EmailAddress.normalize(email));
        return failures != null && failures >= properties.maxFailuresPerEmail();
    }

    public void clearFailures(String email) {
        failuresByEmail.invalidate(EmailAddress.normalize(email));
    }

    /** 记录一次来自该地址的尝试，返回 true 表示已超出每分钟上限。 */
    public boolean registerAttemptAndCheckRateLimit(String clientIp) {
        Integer attempts = attemptsByIp.asMap().merge(clientIp, 1, Integer::sum);
        return attempts > properties.maxAttemptsPerIpPerMinute();
    }

    /**
     * 清空全部计数。目前只有测试隔离监听器调用它——限流状态是进程内单例且被所有集成测试共用，
     * 不在测试方法之间清零会让计数跨测试类累加。尚未对外暴露任何运维接口。
     */
    public void clearAll() {
        failuresByEmail.invalidateAll();
        attemptsByIp.invalidateAll();
    }
}
