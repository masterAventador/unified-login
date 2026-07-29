package com.aventador.unifiedlogin.support;

import com.github.benmanes.caffeine.cache.Ticker;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 可手动推进的时钟。限流的锁定时长以分钟计，用真实等待验证过期会让测试跑十几分钟，
 * 因此把时间源做成可注入的，测试直接把时钟拨到过期之后。
 */
public final class MutableTicker implements Ticker {

    private final AtomicLong nanos = new AtomicLong();

    @Override
    public long read() {
        return nanos.get();
    }

    public void advance(Duration duration) {
        nanos.addAndGet(duration.toNanos());
    }
}
