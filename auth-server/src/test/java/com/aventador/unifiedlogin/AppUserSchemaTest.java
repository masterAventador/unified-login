package com.aventador.unifiedlogin;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Import(PostgresTestConfig.class)
class AppUserSchemaTest {

    @Autowired
    private DataSource dataSource;

    private record ColumnMeta(String typeName, int columnSize, boolean notNull) {
    }

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
    void appUserColumnsHaveExpectedTypeSizeAndNullability() throws Exception {
        Map<String, ColumnMeta> columns = new HashMap<>();
        try (Connection connection = dataSource.getConnection();
             ResultSet rs = connection.getMetaData().getColumns(null, null, "app_user", null)) {
            while (rs.next()) {
                columns.put(rs.getString("COLUMN_NAME"), new ColumnMeta(
                        rs.getString("TYPE_NAME"),
                        rs.getInt("COLUMN_SIZE"),
                        "NO".equals(rs.getString("IS_NULLABLE"))));
            }
        }

        assertThat(columns.get("id").typeName()).isEqualToIgnoringCase("uuid");
        assertThat(columns.get("id").notNull()).isTrue();

        assertThat(columns.get("email").typeName()).isEqualToIgnoringCase("varchar");
        assertThat(columns.get("email").columnSize()).isEqualTo(320);
        assertThat(columns.get("email").notNull()).isTrue();

        assertThat(columns.get("password_hash").typeName()).isEqualToIgnoringCase("varchar");
        assertThat(columns.get("password_hash").columnSize()).isEqualTo(255);
        assertThat(columns.get("password_hash").notNull()).isTrue();

        assertThat(columns.get("status").typeName()).isEqualToIgnoringCase("varchar");
        assertThat(columns.get("status").columnSize()).isEqualTo(16);
        assertThat(columns.get("status").notNull()).isTrue();

        assertThat(columns.get("email_verified").typeName()).isEqualToIgnoringCase("bool");
        assertThat(columns.get("email_verified").notNull()).isTrue();

        assertThat(columns.get("is_platform_admin").typeName()).isEqualToIgnoringCase("bool");
        assertThat(columns.get("is_platform_admin").notNull()).isTrue();

        // 三个时间列必须带时区（timestamptz），不能被静默改成不带时区的 timestamp，
        // 否则认证相关的时间戳在跨时区场景下会算错。
        assertThat(columns.get("password_changed_at").typeName()).isEqualToIgnoringCase("timestamptz");
        assertThat(columns.get("password_changed_at").notNull()).isTrue();

        assertThat(columns.get("created_at").typeName()).isEqualToIgnoringCase("timestamptz");
        assertThat(columns.get("created_at").notNull()).isTrue();

        assertThat(columns.get("updated_at").typeName()).isEqualToIgnoringCase("timestamptz");
        assertThat(columns.get("updated_at").notNull()).isTrue();
    }

    @Test
    void emailHasUniqueSingleColumnIndex() throws Exception {
        Map<String, List<String>> indexColumns = collectIndexColumns(true);

        List<String> emailIndexColumns = indexColumns.values().stream()
                .filter(cols -> cols.contains("email"))
                .findFirst()
                .orElse(null);

        // 必须恰好是单列索引，不能是把 email 和别的列合在一起的复合唯一索引，
        // 否则 email 本身并不具备真正的唯一性约束。
        assertThat(emailIndexColumns)
                .as("email 列应存在只包含 email 一列的唯一索引")
                .containsExactly("email");
    }

    @Test
    void statusHasNonUniqueIndex() throws Exception {
        Map<String, List<String>> indexColumns = collectIndexColumns(false);

        boolean statusIndexExists = indexColumns.getOrDefault("ix_app_user_status", List.of())
                .contains("status");

        assertThat(statusIndexExists)
                .as("app_user.status 列应存在名为 ix_app_user_status 的索引")
                .isTrue();
    }

    private Map<String, List<String>> collectIndexColumns(boolean uniqueOnly) throws Exception {
        Map<String, List<String>> indexColumns = new HashMap<>();
        try (Connection connection = dataSource.getConnection();
             ResultSet rs = connection.getMetaData().getIndexInfo(null, null, "app_user", uniqueOnly, false)) {
            while (rs.next()) {
                String indexName = rs.getString("INDEX_NAME");
                String columnName = rs.getString("COLUMN_NAME");
                if (indexName == null || columnName == null) {
                    continue;
                }
                indexColumns.computeIfAbsent(indexName, key -> new ArrayList<>()).add(columnName);
            }
        }
        return indexColumns;
    }
}
