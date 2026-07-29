package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.EmailAddress;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 邮箱长度上限必须贯穿整条链路，不能只在注册那一段成立。
 *
 * <p>`EmailAddress.MAX_LENGTH` 与 `app_user.email` 都是 320，而框架自带 schema 里存放主体名的
 * `principal_name` 是照抄官方脚本带进来的 varchar(200)。两侧各有测试钉死，中间那道 200 谁都没对过账。
 * 实际后果不是注册失败——注册和登录都会成功，直到用户打开任意产品、走到授权端点写
 * `oauth2_authorization` 时才 500，且该账号在阶段一没有任何补救入口。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class MaxLengthEmailFlowTest {

    private static final String PASSWORD = "a valid password";

    private static final String EMAIL_DOMAIN = "@max-length.example.com";

    /**
     * 所有存放邮箱或以邮箱为值的主体名的列。任一列装不下一个合法邮箱，用户就会卡在链路中段。
     */
    private static final Map<String, String> EMAIL_BEARING_COLUMNS = Map.of(
            "app_user", "email",
            "oauth2_authorization", "principal_name",
            "oauth2_authorization_consent", "principal_name");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private DataSource dataSource;

    /**
     * 终态是「拿着令牌能访问受保护资源」，不是「列宽够用」。只断言列宽的话，将来任何一处新的
     * 长度收窄（比如又抄进来一张官方表）都会重新绕过它。
     */
    @Test
    void maxLengthEmailCompletesAuthorizationCodeFlowIntoWorkingAccessToken() throws Exception {
        String email = maxLengthEmail();
        AppUser user = registrationService.register(email, PASSWORD);

        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                        OAuth2TestFlows.login(mockMvc, email, PASSWORD)));

        assertUserinfoAccessible(OAuth2TestFlows.jsonField(tokenResponse, "access_token"), user);

        // 续期同样要重写 principal_name，30 天里每次刷新都会经过这条路径
        String refreshedResponse = OAuth2TestFlows.refreshTokens(mockMvc,
                OAuth2TestFlows.jsonField(tokenResponse, "refresh_token"));

        assertUserinfoAccessible(OAuth2TestFlows.jsonField(refreshedResponse, "access_token"), user);
    }

    /**
     * 把「邮箱长度上限」与「各表列宽」绑在一起：调大 MAX_LENGTH 却漏了迁移、
     * 或把某一列改窄，任一侧单独变动都会在这里变红。
     */
    @Test
    void everyColumnStoringAnEmailCanHoldMaxLengthEmail() throws Exception {
        for (Map.Entry<String, String> tableColumn : EMAIL_BEARING_COLUMNS.entrySet()) {
            String table = tableColumn.getKey();
            String column = tableColumn.getValue();

            assertThat(columnSize(table, column))
                    .as("%s.%s 必须能装下长度为 EmailAddress.MAX_LENGTH 的邮箱", table, column)
                    .isGreaterThanOrEqualTo(EmailAddress.MAX_LENGTH);
        }
    }

    private void assertUserinfoAccessible(String accessToken, AppUser user) throws Exception {
        mockMvc.perform(get("/userinfo").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value(user.getId().toString()));
    }

    private int columnSize(String table, String column) throws Exception {
        try (Connection connection = dataSource.getConnection();
             ResultSet rs = connection.getMetaData().getColumns(null, null, table, column)) {
            assertThat(rs.next()).as("数据库中应存在列 %s.%s", table, column).isTrue();
            return rs.getInt("COLUMN_SIZE");
        }
    }

    private static String maxLengthEmail() {
        String local = "a".repeat(EmailAddress.MAX_LENGTH - EMAIL_DOMAIN.length());
        String email = local + EMAIL_DOMAIN;
        assertThat(email).hasSize(EmailAddress.MAX_LENGTH);
        return email;
    }
}
