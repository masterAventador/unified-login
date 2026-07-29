package com.aventador.unifiedlogin;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Import(PostgresTestConfig.class)
class AppUserSchemaTest {

    @Autowired
    private DataSource dataSource;

    @Test
    void appUserTableHasAllExpectedColumns() throws Exception {
        Set<String> columns = new HashSet<>();
        try (Connection connection = dataSource.getConnection();
             ResultSet rs = connection.getMetaData().getColumns(null, null, "app_user", null)) {
            while (rs.next()) {
                columns.add(rs.getString("COLUMN_NAME"));
            }
        }

        assertThat(columns).contains(
                "id", "email", "password_hash", "status", "email_verified",
                "is_platform_admin", "password_changed_at", "created_at", "updated_at");
    }

    @Test
    void emailHasUniqueIndex() throws Exception {
        boolean uniqueIndexOnEmail = false;
        try (Connection connection = dataSource.getConnection();
             ResultSet rs = connection.getMetaData().getIndexInfo(null, null, "app_user", true, false)) {
            while (rs.next()) {
                if ("email".equals(rs.getString("COLUMN_NAME"))) {
                    uniqueIndexOnEmail = true;
                }
            }
        }

        assertThat(uniqueIndexOnEmail).isTrue();
    }
}
