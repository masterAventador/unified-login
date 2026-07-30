package com.aventador.unifiedlogin.web;

import com.aventador.unifiedlogin.PostgresTestConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 用一份非默认的锁定时长启动，验证登录页的锁定提示确实读的是配置。
 *
 * <p>只在默认配置下断言「页面写着 15 分钟」是抓不到问题的——文案写死成 15 也一样通过。
 * 必须换一个值再看页面跟不跟着变，才排除得掉文案与配置各写一份、调完配置页面还在骗用户的情况。
 * 代价是一个独立的应用上下文。
 */
@SpringBootTest(properties = "unified-login.login-rate-limit.email-lock-duration=30m")
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class LoginLockNoticeDurationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void lockedNoticeReportsTheConfiguredDuration() throws Exception {
        mockMvc.perform(get("/login").param("locked", ""))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("30 分钟")))
                .andExpect(content().string(not(containsString("15 分钟"))));
    }
}
