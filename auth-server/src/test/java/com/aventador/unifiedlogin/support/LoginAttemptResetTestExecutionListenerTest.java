package com.aventador.unifiedlogin.support;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.security.LoginRateLimitProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 给测试隔离机制本身加回归保护。
 *
 * <p>{@link LoginAttemptResetTestExecutionListener} 一旦失效，症状是某条与限流毫无关系的用例
 * 突然收到 429，排查方向会被完全带偏。下面两个方法各自把每分钟配额整个用满：
 * 只要计数没有在方法之间清零，先跑的那个用完配额，后跑的那个就会提前收到 429 而变红。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class LoginAttemptResetTestExecutionListenerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private LoginRateLimitProperties rateLimitProperties;

    @Test
    void ipCounterStartsFromZero() throws Exception {
        assertFullIpBudgetIsAvailable("first");
    }

    @Test
    void ipCounterStartsFromZeroForTheNextMethodToo() throws Exception {
        assertFullIpBudgetIsAvailable("second");
    }

    private void assertFullIpBudgetIsAvailable(String tag) throws Exception {
        int limit = rateLimitProperties.maxAttemptsPerIpPerMinute();

        // 配额之内的每一次都必须被放行。计数若从上一个测试方法接着算，这里会提前收到 429
        for (int i = 0; i < limit; i++) {
            mockMvc.perform(formLogin("/login").user(tag + "-" + i + "@example.com").password("irrelevant"))
                    .andExpect(status().isFound());
        }

        // 再一次必须超限。缺了这条，限流整个失效时上面的循环会全部放行，本用例就成了永远为真的空断言
        mockMvc.perform(formLogin("/login").user(tag + "-overflow@example.com").password("irrelevant"))
                .andExpect(status().isTooManyRequests());
    }
}
