package com.aventador.unifiedlogin.support;

import com.aventador.unifiedlogin.security.LoginAttemptService;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.support.AbstractTestExecutionListener;

/**
 * 每个测试方法开始前清空登录限流计数。
 *
 * <p>限流计数是进程内单例，而所有 {@code @SpringBootTest} 共用同一个应用上下文，
 * 计数会跨测试类累加：只要全套测试里的登录次数超过每分钟上限，某个完全无关的用例就会突然收到 429。
 * 靠各个测试类自己记得清零太容易漏，这里集中处理，效果与框架自带的
 * {@code MockitoResetTestExecutionListener} 一致。
 *
 * <p>通过 {@code src/test/resources/META-INF/spring.factories} 注册为默认监听器。
 */
public class LoginAttemptResetTestExecutionListener extends AbstractTestExecutionListener {

    @Override
    public void beforeTestMethod(TestContext testContext) {
        // 切片测试的上下文里没有这个 Bean，跳过即可
        testContext.getApplicationContext()
                .getBeanProvider(LoginAttemptService.class)
                .ifAvailable(LoginAttemptService::clearAll);
    }
}
