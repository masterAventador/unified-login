# 统一登录 · 阶段一（地基）实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建成认证中心的可运行地基——用户能在浏览器完成邮箱注册，并通过标准 OIDC 授权码 + PKCE 流程登录 demo-web-a。

**Architecture:** 单体 Spring Boot 应用，Spring Authorization Server 提供 OIDC 协议端点，Thymeleaf 渲染注册与登录页，PostgreSQL 存储用户与授权数据，Flyway 管理表结构。用户域（`user` 包）不依赖任何上层包；注册、密码、Web 层单向依赖它。

**Tech Stack:** Java 17、Spring Boot 4.1.0、Spring Security / Spring Authorization Server 7.1.0、PostgreSQL 16、Flyway 12、Thymeleaf、JUnit 5、Testcontainers 2.0.5、Playwright。

配套规格书：`docs/superpowers/specs/2026-07-29-unified-login-design.md`

## Global Constraints

以下约束对**每一个** Task 都生效，实现时不得违反：

- **TDD 铁律**：先写测试 → 运行并亲眼看到失败 → 写最小实现 → 运行确认通过 → 提交。不允许先写实现后补测试。
- **Java 版本**：17（`<java.version>17</java.version>`）。这是开发机既有的 JDK，也是 Spring Boot 4.1 的最低要求版本。**不要为本项目升级或切换 JDK**——开发机上其他项目依赖当前环境。
- **Spring Boot 版本**：`4.1.0`。Spring Security 与 Spring Authorization Server 的版本由它统一管理为 `7.1.0`，**不要在 pom 中写死这两个版本号**。
- **⚠ 包重定位（照旧文档写会编译失败）**：Spring Authorization Server 并入 Spring Security 7 后，两个配置类换了包：
  - `org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer`
  - `org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration`
  - 其余类（`RegisteredClient`、`AuthorizationServerSettings`、`JdbcRegisteredClientRepository`、`JdbcOAuth2AuthorizationService`）包路径**未变**，仍在 `org.springframework.security.oauth2.server.authorization.*` 下。
- **⚠ 测试授权码流程必须走真实表单登录，不能用 `.with(user(...))`**：Spring Security 7
  签发 token 时要从主体的 `FactorGrantedAuthority` 推导认证时间，而 `.with(user(...))`
  造的主体没有该 authority，会抛 `authenticationTime cannot be null`。用
  `OAuth2TestFlows.login(...)` 拿到会话再 `.session(session)` 调授权端点。
- **⚠ `@DynamicPropertySource` 只在测试类中生效**：放在 `@TestConfiguration`/`@Configuration`
  类里会被**静默忽略**——属性没被覆盖、测试照常通过，缺陷完全不可见。要在配置类里注册
  动态属性，用 `@Bean DynamicPropertyRegistrar`（Spring Framework 7 提供）。
- **⚠ MockMvc 测授权端点必须把参数放进 query string，不能用 `.param()`**：框架的
  `OAuth2EndpointUtils.getQueryParameters` 会用 `request.getQueryString()` 过滤参数，
  而 MockMvc 的 `.param()` 只填 parameterMap、不填 queryString，导致所有授权参数被
  静默丢弃、端点报 `invalid_request: response_type`。GET `/oauth2/authorize` 一律写成
  `get("/oauth2/authorize?response_type=code&...")`。（POST `/oauth2/token` 不受影响，
  它走 form 参数路径，`.param()` 正常。）
- **⚠ OAuth2AuthorizationServerConfigurer 在 Security 7 无 `authorizationServer()` 静态工厂**：
  旧 1.x 文档的 `OAuth2AuthorizationServerConfigurer.authorizationServer()` 已不存在，
  使用无参构造 `new OAuth2AuthorizationServerConfigurer()`。
- **⚠ 测试注解同样被 Boot 4.x 模块化拆分**：`@AutoConfigureMockMvc` 不在旧包
  `org.springframework.boot.test.autoconfigure.web.servlet`（该包在 4.1 的
  spring-boot-test-autoconfigure 里已不存在），现位于
  `org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc`，
  需要 test 依赖 `spring-boot-starter-webmvc-test`（Task 5 起已加入 pom）。
- **⚠ Testcontainers 2.x 坐标与包路径均已更名**：artifactId 必须带 `testcontainers-` 前缀（`testcontainers-postgresql`、`testcontainers-junit-jupiter`），容器类在 `org.testcontainers.postgresql.PostgreSQLContainer` 且**不再是泛型类**（不要写 `<?>`）。
- **⚠ BouncyCastle 必须显式声明版本**：Spring Boot 4.1 不管理它，而 `Argon2PasswordEncoder` 运行时依赖它。使用 `org.bouncycastle:bcprov-jdk18on:1.85`。
- **Java 包名**：`com.aventador.unifiedlogin`。
- **Argon2id 参数**：`saltLength=16, hashLength=32, parallelism=1, memory=19456, iterations=2`，即 `new Argon2PasswordEncoder(16, 32, 1, 19456, 2)`。
- **密码长度**：8–64 字符，不限制字符类型。
- **邮箱**：存储前 `trim` + 转小写；唯一索引建在该小写值上；最大长度 320。
- **Token 与会话**：access token 15 分钟；refresh token 30 天且**轮转**（`reuseRefreshTokens(false)`）；会话 Cookie 14 天。ID token 寿命由框架绑定为等于 access token，**不可配置**。
- **所有 client**：public client（`ClientAuthenticationMethod.NONE`）、**强制 PKCE**（`requireProofKey(true)`）、跳过同意页（`requireAuthorizationConsent(false)`）。
- **Cookie 属性**：`HttpOnly`、`Secure`、`SameSite=Lax`。本地开发同样保持 `Secure=true`——浏览器将 `localhost` 视为安全上下文，因此**代码中不得出现任何"本地关闭 Secure"的条件分支**。
- **提交信息用中文**，不添加任何 AI 署名。

### 阶段一的已知限制（不在本阶段解决，不要视为缺陷）

- **会话存储在应用内存中**，认证中心重启会导致所有用户需重新登录。持久化会话留待后续阶段。
- 修改密码、管理后台、静默续签不在本阶段范围内。
- 登录失败限流的计数状态同样保存在应用内存中，仅适用于单实例部署。多实例部署需改用共享存储，届时再处理。

## File Structure

```
auth-server/
├── pom.xml                                    Maven 构建与依赖
├── src/main/java/com/aventador/unifiedlogin/
│   ├── AuthServerApplication.java             启动类
│   ├── user/
│   │   ├── EmailAddress.java                  邮箱值对象：规范化 + 格式校验
│   │   ├── InvalidEmailException.java         邮箱非法异常
│   │   ├── AppUser.java                       用户 JPA 实体
│   │   ├── UserStatus.java                    账号状态枚举
│   │   ├── AppUserRepository.java             Spring Data 仓储
│   │   └── UserService.java                   建号、按邮箱查号、唯一性判定
│   ├── password/
│   │   ├── PasswordPolicy.java                密码强度规则（纯静态）
│   │   ├── WeakPasswordException.java         密码不合规异常
│   │   └── PasswordConfig.java                Argon2id 编码器 Bean
│   ├── registration/
│   │   ├── RegistrationService.java           注册用例
│   │   └── EmailAlreadyRegisteredException.java
│   ├── web/
│   │   ├── RegistrationController.java        注册页与表单提交
│   │   ├── LoginController.java               登录页渲染
│   ├── config/
│   │   ├── SecurityConfig.java                两条过滤链 + 表单登录
│   │   ├── AuthorizationServerConfig.java     SAS 配置、JWKSource、settings
│   │   ├── RsaKeyProvider.java                RSA 密钥持久化与加载
│   │   ├── UnifiedLoginProperties.java        自定义配置绑定
│   │   └── ClientSyncRunner.java              启动时同步 client 配置入库
│   └── security/
│       └── AppUserDetailsService.java         把 AppUser 适配为 UserDetails
├── src/main/resources/
│   ├── application.yml
│   ├── db/migration/
│   │   ├── V1__create_app_user.sql
│   │   └── V2__oauth2_server_tables.sql
│   └── templates/
│       ├── register.html
│       └── login.html
└── src/test/java/com/aventador/unifiedlogin/   （与源码同包路径）
    ├── PostgresTestConfig.java                Testcontainers 共用配置
    └── ...各 Task 的测试

demo/demo-web-a/                                极简 Vite + TS SPA
e2e/                                            Playwright 端到端用例
```

---

### Task 1: 项目骨架、数据库连接与 app_user 表

**Files:**
- Create: `auth-server/pom.xml`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/AuthServerApplication.java`
- Create: `auth-server/src/main/resources/application.yml`
- Create: `auth-server/src/main/resources/db/migration/V1__create_app_user.sql`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/PostgresTestConfig.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/AppUserSchemaTest.java`

**Interfaces:**
- Consumes: 无（首个任务）
- Produces: `PostgresTestConfig`（供后续所有集成测试 `@Import`）；数据库表 `app_user`

- [ ] **Step 1: 创建 pom.xml 并生成 Maven wrapper**

先写下面的 `auth-server/pom.xml`，然后在 `auth-server/` 目录下执行 `mvn -N wrapper:wrapper` 生成 `mvnw`、`mvnw.cmd` 与 `.mvn/wrapper/`。后续所有步骤都用 `./mvnw` 而非 `mvn`，以锁定构建工具版本。生成后把 wrapper 文件一并纳入版本控制。

**⚠ 生成后必须检查 `.mvn/wrapper/maven-wrapper.properties` 的 `distributionUrl`。** 如果开发机的 `~/.m2/settings.xml` 配置了私服镜像，`wrapper:wrapper` 会把那个内网地址写进生成文件，提交后其他机器与 CI 上 `./mvnw` 的第一步下载就会失败。该值必须是公共地址：

```properties
distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.13/apache-maven-3.9.13-bin.zip
```

本机私服加速属于本机基础设施，通过环境变量或本机 `settings.xml` 解决，**不得写进提交到仓库的文件**。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>4.1.0</version>
        <relativePath/>
    </parent>

    <groupId>com.aventador</groupId>
    <artifactId>auth-server</artifactId>
    <version>0.1.0-SNAPSHOT</version>
    <name>unified-login-auth-server</name>

    <properties>
        <java.version>17</java.version>
        <bouncycastle.version>1.85</bouncycastle.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-authorization-server</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        <dependency>
            <groupId>org.flywaydb</groupId>
            <artifactId>flyway-core</artifactId>
        </dependency>
        <dependency>
            <groupId>org.flywaydb</groupId>
            <artifactId>flyway-database-postgresql</artifactId>
        </dependency>
        <!-- 必需：Spring Boot 4.x 把 FlywayAutoConfiguration 拆成了独立模块。
             缺少它时自动配置会被静默跳过——不报错，但迁移永远不执行 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-flyway</artifactId>
        </dependency>
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>
        <!-- Argon2PasswordEncoder 的运行时依赖，Spring Boot 不管理其版本 -->
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-jdk18on</artifactId>
            <version>${bouncycastle.version}</version>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <!-- 必需：Boot 4.x 把 MockMvc 测试自动配置拆到独立模块，
             @AutoConfigureMockMvc 现位于 org.springframework.boot.webmvc.test.autoconfigure -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-webmvc-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-testcontainers</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>testcontainers-postgresql</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>testcontainers-junit-jupiter</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

- [ ] **Step 2: 创建启动类**

`auth-server/src/main/java/com/aventador/unifiedlogin/AuthServerApplication.java`

```java
package com.aventador.unifiedlogin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }
}
```

- [ ] **Step 3: 创建 application.yml**

`auth-server/src/main/resources/application.yml`

```yaml
server:
  port: 9000
  servlet:
    session:
      timeout: 14d
      cookie:
        name: AUTH_SESSION
        http-only: true
        secure: true
        same-site: lax

spring:
  application:
    name: unified-login-auth-server
  datasource:
    url: ${DB_URL:jdbc:postgresql://localhost:5432/unified_login}
    username: ${DB_USERNAME:unified_login}
    password: ${DB_PASSWORD:unified_login}
  jpa:
    hibernate:
      ddl-auto: validate
    open-in-view: false
  flyway:
    enabled: true
    locations: classpath:db/migration
```

- [ ] **Step 4: 创建 Testcontainers 共用配置**

`auth-server/src/test/java/com/aventador/unifiedlogin/PostgresTestConfig.java`

注意 import 路径与非泛型写法，这是 Testcontainers 2.x 的形式：

```java
package com.aventador.unifiedlogin;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistrar;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@TestConfiguration(proxyBeanMethods = false)
public class PostgresTestConfig {

    @Bean
    @ServiceConnection
    PostgreSQLContainer postgresContainer() {
        return new PostgreSQLContainer("postgres:16-alpine");
    }

    /**
     * 所有加载完整上下文的测试都会实例化 JWKSource，从而按配置路径生成一把真实 RSA 私钥。
     * 这里统一把密钥路径改写到临时目录：否则每次跑测试都会在项目目录下落一把真私钥，
     * 且「首次生成」分支因文件已存在而不再被执行。
     *
     * 用 DynamicPropertyRegistrar 而非 @DynamicPropertySource：**后者只在测试类中被扫描，
     * 放在配置类里会被静默忽略**（隔离看似生效、实际完全没起作用）。
     */
    @Bean
    DynamicPropertyRegistrar jwtKeyStoreRegistrar() throws IOException {
        Path keyDir = Files.createTempDirectory("unified-login-test-keys");
        keyDir.toFile().deleteOnExit();
        return (registry) -> registry.add("unified-login.jwt-key-store",
                () -> keyDir.resolve("jwt-signing-key.json").toString());
    }
}
```

- [ ] **Step 5: 写失败的测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/AppUserSchemaTest.java`

```java
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
```

- [ ] **Step 6: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=AppUserSchemaTest`
Expected: FAIL — `app_user` 表不存在，两个断言均失败（columns 为空集合）

- [ ] **Step 7: 写 Flyway 迁移脚本**

`auth-server/src/main/resources/db/migration/V1__create_app_user.sql`

```sql
CREATE TABLE app_user (
    id                  uuid         NOT NULL,
    email               varchar(320) NOT NULL,
    password_hash       varchar(255) NOT NULL,
    status              varchar(16)  NOT NULL DEFAULT 'ACTIVE',
    email_verified      boolean      NOT NULL DEFAULT true,
    is_platform_admin   boolean      NOT NULL DEFAULT false,
    password_changed_at timestamptz  NOT NULL,
    created_at          timestamptz  NOT NULL,
    updated_at          timestamptz  NOT NULL,
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX ux_app_user_email ON app_user (email);
CREATE INDEX ix_app_user_status ON app_user (status);
```

- [ ] **Step 8: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=AppUserSchemaTest`
Expected: PASS，两个测试均通过

- [ ] **Step 9: 提交**

```bash
git add auth-server/pom.xml auth-server/mvnw auth-server/mvnw.cmd auth-server/.mvn auth-server/src
git commit -m "feat(auth-server): 搭建项目骨架并建立 app_user 表

引入 Spring Boot 4.1 与授权服务器 starter，接入 PostgreSQL 与
Flyway，用 Testcontainers 验证表结构与邮箱唯一索引。"
```

---

### Task 2: 邮箱规范化与格式校验

**Files:**
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/user/EmailAddress.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/user/InvalidEmailException.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/user/EmailAddressTest.java`

**Interfaces:**
- Consumes: 无
- Produces: `EmailAddress`（record，构造器即校验；`value()` 返回规范化后的小写邮箱）、`EmailAddress.MAX_LENGTH`、`EmailAddress.normalize(String): String`（只规范化不校验，Task 11 的限流会用它）、`InvalidEmailException`

- [ ] **Step 1: 写失败的测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/user/EmailAddressTest.java`

```java
package com.aventador.unifiedlogin.user;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EmailAddressTest {

    @Test
    void trimsSurroundingWhitespace() {
        assertThat(new EmailAddress("  user@example.com  ").value()).isEqualTo("user@example.com");
    }

    @Test
    void convertsToLowerCase() {
        assertThat(new EmailAddress("User@Example.COM").value()).isEqualTo("user@example.com");
    }

    @Test
    void treatsDifferentCasesAsEqual() {
        assertThat(new EmailAddress("User@Example.com")).isEqualTo(new EmailAddress("user@example.com"));
    }

    @Test
    void rejectsNull() {
        assertThatThrownBy(() -> new EmailAddress(null)).isInstanceOf(InvalidEmailException.class);
    }

    @Test
    void rejectsBlank() {
        assertThatThrownBy(() -> new EmailAddress("   ")).isInstanceOf(InvalidEmailException.class);
    }

    @Test
    void rejectsMissingAtSign() {
        assertThatThrownBy(() -> new EmailAddress("userexample.com")).isInstanceOf(InvalidEmailException.class);
    }

    @Test
    void rejectsMissingDomainDot() {
        assertThatThrownBy(() -> new EmailAddress("user@example")).isInstanceOf(InvalidEmailException.class);
    }

    @Test
    void rejectsInternalWhitespace() {
        assertThatThrownBy(() -> new EmailAddress("us er@example.com")).isInstanceOf(InvalidEmailException.class);
    }

    @Test
    void rejectsTooLong() {
        String local = "a".repeat(EmailAddress.MAX_LENGTH);
        assertThatThrownBy(() -> new EmailAddress(local + "@example.com"))
                .isInstanceOf(InvalidEmailException.class);
    }

    @Test
    void acceptsEmailOfExactlyMaxLength() {
        // 边界正向锁定：若长度判断被误改为 >=，此用例失败
        String local = "a".repeat(EmailAddress.MAX_LENGTH - "@example.com".length());
        assertThat(new EmailAddress(local + "@example.com").value()).hasSize(EmailAddress.MAX_LENGTH);
    }

    @Test
    void acceptsPlusAddressing() {
        assertThat(new EmailAddress("user+tag@example.com").value()).isEqualTo("user+tag@example.com");
    }

    @Test
    void normalizeLowercasesAndTrimsWithoutValidating() {
        // 供登录限流等场景使用：对非法格式的输入也要能得到稳定的归一化键
        assertThat(EmailAddress.normalize("  User@Example.COM ")).isEqualTo("user@example.com");
        assertThat(EmailAddress.normalize("not-an-email")).isEqualTo("not-an-email");
    }

    @Test
    void normalizeTreatsNullAsEmptyString() {
        assertThat(EmailAddress.normalize(null)).isEmpty();
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=EmailAddressTest`
Expected: FAIL — 编译错误，`EmailAddress` 与 `InvalidEmailException` 尚不存在

- [ ] **Step 3: 写异常类**

`auth-server/src/main/java/com/aventador/unifiedlogin/user/InvalidEmailException.java`

```java
package com.aventador.unifiedlogin.user;

public class InvalidEmailException extends RuntimeException {

    public InvalidEmailException(String message) {
        super(message);
    }
}
```

- [ ] **Step 4: 写 EmailAddress**

`auth-server/src/main/java/com/aventador/unifiedlogin/user/EmailAddress.java`

紧凑构造器在赋值前完成规范化，因此任何路径构造出的实例都持有已规范化的值：

```java
package com.aventador.unifiedlogin.user;

import java.util.Locale;
import java.util.regex.Pattern;

public record EmailAddress(String value) {

    public static final int MAX_LENGTH = 320;

    private static final Pattern PATTERN = Pattern.compile("^[^@\\s]+@[^@\\s.]+(\\.[^@\\s.]+)+$");

    public EmailAddress {
        // normalize 已把 null 归一为空串，isEmpty 分支同时覆盖 null 与空白输入
        value = normalize(value);
        if (value.isEmpty()) {
            throw new InvalidEmailException("邮箱不能为空");
        }
        if (value.length() > MAX_LENGTH) {
            throw new InvalidEmailException("邮箱长度不能超过 " + MAX_LENGTH + " 个字符");
        }
        if (!PATTERN.matcher(value).matches()) {
            throw new InvalidEmailException("邮箱格式不正确");
        }
    }

    /**
     * 只做规范化，不做任何校验。用于必须对非法输入也一致处理的场景——
     * 例如登录失败限流，对不存在或格式错误的邮箱同样要计数，否则「会不会被锁」
     * 本身就泄漏了账号是否存在。
     */
    public static String normalize(String raw) {
        return (raw == null) ? "" : raw.trim().toLowerCase(Locale.ROOT);
    }
}
```

- [ ] **Step 5: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=EmailAddressTest`
Expected: PASS，13 个测试全部通过

- [ ] **Step 6: 提交**

```bash
git add auth-server/src/main/java/com/aventador/unifiedlogin/user auth-server/src/test/java/com/aventador/unifiedlogin/user
git commit -m "feat(user): 新增邮箱值对象

构造时统一去空白并转小写，校验格式与长度上限，
使大小写不同的同一邮箱视为同一个账号。"
```

---

### Task 3: 密码强度规则与 Argon2id 编码器

**Files:**
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/password/PasswordPolicy.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/password/WeakPasswordException.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/password/PasswordConfig.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/password/PasswordPolicyTest.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/password/PasswordEncoderIntegrationTest.java`

**Interfaces:**
- Consumes: 无
- Produces: `PasswordPolicy.validate(String)`（不合规抛 `WeakPasswordException`）、`PasswordPolicy.MIN_LENGTH` / `MAX_LENGTH`、Spring 容器中的 `PasswordEncoder` Bean

- [ ] **Step 1: 写失败的单元测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/password/PasswordPolicyTest.java`

```java
package com.aventador.unifiedlogin.password;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordPolicyTest {

    @Test
    void acceptsMinimumLength() {
        assertThatCode(() -> PasswordPolicy.validate("a".repeat(PasswordPolicy.MIN_LENGTH)))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsMaximumLength() {
        assertThatCode(() -> PasswordPolicy.validate("a".repeat(PasswordPolicy.MAX_LENGTH)))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsTooShort() {
        assertThatThrownBy(() -> PasswordPolicy.validate("a".repeat(PasswordPolicy.MIN_LENGTH - 1)))
                .isInstanceOf(WeakPasswordException.class);
    }

    @Test
    void rejectsTooLong() {
        assertThatThrownBy(() -> PasswordPolicy.validate("a".repeat(PasswordPolicy.MAX_LENGTH + 1)))
                .isInstanceOf(WeakPasswordException.class);
    }

    @Test
    void rejectsNull() {
        assertThatThrownBy(() -> PasswordPolicy.validate(null)).isInstanceOf(WeakPasswordException.class);
    }

    @Test
    void doesNotRequireCharacterVariety() {
        assertThatCode(() -> PasswordPolicy.validate("correct horse battery staple"))
                .doesNotThrowAnyException();
    }

    @Test
    void doesNotTrimPassword() {
        assertThatCode(() -> PasswordPolicy.validate("  spaced  ")).doesNotThrowAnyException();
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=PasswordPolicyTest`
Expected: FAIL — 编译错误，`PasswordPolicy` 与 `WeakPasswordException` 尚不存在

- [ ] **Step 3: 写异常类与策略类**

`auth-server/src/main/java/com/aventador/unifiedlogin/password/WeakPasswordException.java`

```java
package com.aventador.unifiedlogin.password;

public class WeakPasswordException extends RuntimeException {

    public WeakPasswordException(String message) {
        super(message);
    }
}
```

`auth-server/src/main/java/com/aventador/unifiedlogin/password/PasswordPolicy.java`

全部成员均为静态，故声明为 final 并私有化构造器：

```java
package com.aventador.unifiedlogin.password;

public final class PasswordPolicy {

    public static final int MIN_LENGTH = 8;
    public static final int MAX_LENGTH = 64;

    private PasswordPolicy() {
    }

    public static void validate(String rawPassword) {
        if (rawPassword == null) {
            throw new WeakPasswordException("密码不能为空");
        }
        if (rawPassword.length() < MIN_LENGTH) {
            throw new WeakPasswordException("密码长度不能少于 " + MIN_LENGTH + " 个字符");
        }
        if (rawPassword.length() > MAX_LENGTH) {
            throw new WeakPasswordException("密码长度不能超过 " + MAX_LENGTH + " 个字符");
        }
    }
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=PasswordPolicyTest`
Expected: PASS，7 个测试全部通过

- [ ] **Step 5: 写编码器的失败测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/password/PasswordEncoderIntegrationTest.java`

```java
package com.aventador.unifiedlogin.password;

import com.aventador.unifiedlogin.PostgresTestConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Import(PostgresTestConfig.class)
class PasswordEncoderIntegrationTest {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void producesArgon2idHash() {
        String hash = passwordEncoder.encode("correct horse battery staple");
        assertThat(hash).startsWith("$argon2id$");
    }

    @Test
    void verifiesCorrectPassword() {
        String hash = passwordEncoder.encode("correct horse battery staple");
        assertThat(passwordEncoder.matches("correct horse battery staple", hash)).isTrue();
    }

    @Test
    void rejectsWrongPassword() {
        String hash = passwordEncoder.encode("correct horse battery staple");
        assertThat(passwordEncoder.matches("wrong password here", hash)).isFalse();
    }

    @Test
    void producesDifferentHashesForSamePasswordDueToSalt() {
        String first = passwordEncoder.encode("same password value");
        String second = passwordEncoder.encode("same password value");
        assertThat(first).isNotEqualTo(second);
    }
}
```

- [ ] **Step 6: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=PasswordEncoderIntegrationTest`
Expected: FAIL — 容器中不存在 `PasswordEncoder` Bean，启动失败

- [ ] **Step 7: 写编码器配置**

`auth-server/src/main/java/com/aventador/unifiedlogin/password/PasswordConfig.java`

构造器参数顺序为 `(saltLength, hashLength, parallelism, memory, iterations)`，memory 单位为 KiB：

```java
package com.aventador.unifiedlogin.password;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {

    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;
    private static final int PARALLELISM = 1;
    private static final int MEMORY_KIB = 19456;
    private static final int ITERATIONS = 2;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(SALT_LENGTH, HASH_LENGTH, PARALLELISM, MEMORY_KIB, ITERATIONS);
    }
}
```

- [ ] **Step 8: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=PasswordEncoderIntegrationTest`
Expected: PASS，4 个测试全部通过。若报 `NoClassDefFoundError: org/bouncycastle/crypto/generators/Argon2BytesGenerator`，说明 Task 1 的 BouncyCastle 依赖未正确引入

- [ ] **Step 9: 提交**

```bash
git add auth-server/src/main/java/com/aventador/unifiedlogin/password auth-server/src/test/java/com/aventador/unifiedlogin/password
git commit -m "feat(password): 新增密码强度规则与 Argon2id 编码器

按 NIST 建议只校验长度区间不强制字符类型，采用 OWASP 推荐的
Argon2id 参数做密码哈希。"
```

---

### Task 4: 用户持久化与 UserService

**Files:**
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/user/UserStatus.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/user/AppUser.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/user/AppUserRepository.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/user/UserService.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/user/UserServiceTest.java`

**Interfaces:**
- Consumes: `EmailAddress`（Task 2）、`PostgresTestConfig`（Task 1）
- Produces:
  - `UserStatus`：枚举 `ACTIVE` / `DISABLED`
  - `AppUser`：实体，暴露 `getId(): UUID`、`getEmail(): String`、`getPasswordHash(): String`、`getStatus(): UserStatus`、`isPlatformAdmin(): boolean`、`getPasswordChangedAt(): Instant`
  - `AppUserRepository.findByEmail(String): Optional<AppUser>`、`existsByEmail(String): boolean`
  - `UserService.createUser(EmailAddress, String passwordHash): AppUser`、`UserService.findByEmail(EmailAddress): Optional<AppUser>`、`UserService.emailExists(EmailAddress): boolean`

- [ ] **Step 1: 写失败的测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/user/UserServiceTest.java`

```java
package com.aventador.unifiedlogin.user;

import com.aventador.unifiedlogin.PostgresTestConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Import(PostgresTestConfig.class)
class UserServiceTest {

    @Autowired
    private UserService userService;

    @Autowired
    private AppUserRepository repository;

    @Test
    void createsUserWithActiveStatusAndGeneratedId() {
        AppUser user = userService.createUser(new EmailAddress("create@example.com"), "hash-value");

        assertThat(user.getId()).isNotNull();
        assertThat(user.getEmail()).isEqualTo("create@example.com");
        assertThat(user.getPasswordHash()).isEqualTo("hash-value");
        assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
        assertThat(user.isPlatformAdmin()).isFalse();
        assertThat(user.getPasswordChangedAt()).isNotNull();
    }

    @Test
    void persistsEmailInLowerCase() {
        userService.createUser(new EmailAddress("MiXeD@Example.COM"), "hash-value");

        assertThat(repository.findByEmail("mixed@example.com")).isPresent();
    }

    @Test
    void findsUserRegardlessOfInputCase() {
        userService.createUser(new EmailAddress("lookup@example.com"), "hash-value");

        Optional<AppUser> found = userService.findByEmail(new EmailAddress("LookUp@Example.com"));

        assertThat(found).isPresent();
    }

    @Test
    void reportsExistingEmail() {
        userService.createUser(new EmailAddress("exists@example.com"), "hash-value");

        assertThat(userService.emailExists(new EmailAddress("exists@example.com"))).isTrue();
        assertThat(userService.emailExists(new EmailAddress("absent@example.com"))).isFalse();
    }

    @Test
    void returnsEmptyForUnknownEmail() {
        assertThat(userService.findByEmail(new EmailAddress("unknown@example.com"))).isEmpty();
    }

    @Test
    void brandNewEntityReportsIsNewUntilPersisted() {
        // Persistable 契约：新实体 save 前 isNew=true（使 save 走 persist 而非 merge），持久化后翻转
        AppUser user = new AppUser(UUID.randomUUID(), new EmailAddress("persistable@example.com"),
                "hash-value", Instant.now());
        assertThat(user.isNew()).isTrue();

        repository.save(user);

        assertThat(user.isNew()).isFalse();
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=UserServiceTest`
Expected: FAIL — 编译错误，`UserService`、`AppUser`、`AppUserRepository`、`UserStatus` 尚不存在

- [ ] **Step 3: 写枚举与实体**

`auth-server/src/main/java/com/aventador/unifiedlogin/user/UserStatus.java`

```java
package com.aventador.unifiedlogin.user;

public enum UserStatus {
    ACTIVE,
    DISABLED
}
```

`auth-server/src/main/java/com/aventador/unifiedlogin/user/AppUser.java`

```java
package com.aventador.unifiedlogin.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import org.springframework.data.domain.Persistable;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "app_user")
public class AppUser implements Persistable<UUID> {

    @Id
    private UUID id;

    /**
     * ID 由应用层生成而非数据库自增，Spring Data 无法用「id 是否为 null」判定新旧实体。
     * 不实现 Persistable 时 save() 会走 merge()，对每个新实体多打一次冗余 SELECT。
     */
    @Transient
    private boolean isNew = false;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserStatus status;

    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified;

    @Column(name = "is_platform_admin", nullable = false)
    private boolean platformAdmin;

    @Column(name = "password_changed_at", nullable = false)
    private Instant passwordChangedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected AppUser() {
        // JPA 要求的无参构造器
    }

    // 构造器收 EmailAddress 而非裸 String：「落库小写」由类型系统保证，不靠调用方自觉
    AppUser(UUID id, EmailAddress email, String passwordHash, Instant now) {
        this.id = id;
        this.email = email.value();
        this.passwordHash = passwordHash;
        this.status = UserStatus.ACTIVE;
        this.emailVerified = true;
        this.platformAdmin = false;
        this.passwordChangedAt = now;
        this.createdAt = now;
        this.updatedAt = now;
        this.isNew = true;
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }

    @PostPersist
    @PostLoad
    void markNotNew() {
        this.isNew = false;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public UserStatus getStatus() {
        return status;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public boolean isPlatformAdmin() {
        return platformAdmin;
    }

    public Instant getPasswordChangedAt() {
        return passwordChangedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
```

- [ ] **Step 4: 写仓储与服务**

`auth-server/src/main/java/com/aventador/unifiedlogin/user/AppUserRepository.java`

```java
package com.aventador.unifiedlogin.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface AppUserRepository extends JpaRepository<AppUser, UUID> {

    Optional<AppUser> findByEmail(String email);

    boolean existsByEmail(String email);
}
```

`auth-server/src/main/java/com/aventador/unifiedlogin/user/UserService.java`

这是 Spring 管理的 Bean，持有注入的仓储作为实例状态，因此使用实例方法：

```java
package com.aventador.unifiedlogin.user;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    private final AppUserRepository repository;

    public UserService(AppUserRepository repository) {
        this.repository = repository;
    }

    /**
     * 并发注册同一邮箱撞唯一索引时，原样抛出 DataIntegrityViolationException——
     * 本层不掌握业务语义，由注册服务负责转译为领域异常。
     * 用 saveAndFlush 而非 save：立即执行 INSERT，保证冲突异常在本方法调用点显现，
     * 而不是延迟到外层事务提交时才冒出来（那时调用方的 catch 已经抓不住了）。
     */
    @Transactional
    public AppUser createUser(EmailAddress email, String passwordHash) {
        AppUser user = new AppUser(UUID.randomUUID(), email, passwordHash, Instant.now());
        return repository.saveAndFlush(user);
    }

    @Transactional(readOnly = true)
    public Optional<AppUser> findByEmail(EmailAddress email) {
        return repository.findByEmail(email.value());
    }

    @Transactional(readOnly = true)
    public boolean emailExists(EmailAddress email) {
        return repository.existsByEmail(email.value());
    }
}
```

- [ ] **Step 5: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=UserServiceTest`
Expected: PASS，6 个测试全部通过。`ddl-auto: validate` 会同时校验实体与 Task 1 建的表结构一致

- [ ] **Step 6: 提交**

```bash
git add auth-server/src/main/java/com/aventador/unifiedlogin/user auth-server/src/test/java/com/aventador/unifiedlogin/user
git commit -m "feat(user): 新增用户实体、仓储与用户服务

新建账号默认为启用状态且非管理员，邮箱以小写形式落库，
查询时不受输入大小写影响。"
```

---

### Task 5: 注册用例与注册页

**Files:**
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/registration/RegistrationService.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/registration/EmailAlreadyRegisteredException.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/web/RegistrationController.java`
- Create: `auth-server/src/main/resources/templates/register.html`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/config/SecurityConfig.java`
- Modify: `auth-server/src/main/java/com/aventador/unifiedlogin/user/UserService.java`（save 改 saveAndFlush，见 Step 3）
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/registration/RegistrationServiceTest.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/registration/RegistrationServiceConcurrencyTest.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/web/RegistrationControllerTest.java`

**Interfaces:**
- Consumes: `UserService`、`EmailAddress`、`PasswordPolicy`、`PasswordEncoder`
- Produces: `RegistrationService.register(String rawEmail, String rawPassword): AppUser`、`EmailAlreadyRegisteredException`、`SecurityConfig`（后续 Task 6 与 Task 8 会继续修改该文件）

- [ ] **Step 1: 写失败的服务测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/registration/RegistrationServiceTest.java`

```java
package com.aventador.unifiedlogin.registration;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.password.WeakPasswordException;
import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.InvalidEmailException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@Import(PostgresTestConfig.class)
class RegistrationServiceTest {

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void storesHashedPasswordNotRawPassword() {
        AppUser user = registrationService.register("hashing@example.com", "a valid password");

        assertThat(user.getPasswordHash()).isNotEqualTo("a valid password");
        assertThat(passwordEncoder.matches("a valid password", user.getPasswordHash())).isTrue();
    }

    @Test
    void rejectsDuplicateEmailIgnoringCase() {
        registrationService.register("dup@example.com", "a valid password");

        assertThatThrownBy(() -> registrationService.register("DUP@Example.com", "a valid password"))
                .isInstanceOf(EmailAlreadyRegisteredException.class);
    }

    @Test
    void rejectsInvalidEmail() {
        assertThatThrownBy(() -> registrationService.register("not-an-email", "a valid password"))
                .isInstanceOf(InvalidEmailException.class);
    }

    @Test
    void rejectsWeakPassword() {
        assertThatThrownBy(() -> registrationService.register("weak@example.com", "short"))
                .isInstanceOf(WeakPasswordException.class);
    }

    @Test
    void doesNotCreateUserWhenPasswordRejected() {
        assertThatThrownBy(() -> registrationService.register("rollback@example.com", "short"))
                .isInstanceOf(WeakPasswordException.class);

        assertThat(registrationService.isEmailTaken("rollback@example.com")).isFalse();
    }
}
```

第二个测试文件 `auth-server/src/test/java/com/aventador/unifiedlogin/registration/RegistrationServiceConcurrencyTest.java`。
两个并发注册同时穿过查重的竞态无法在真实数据库测试里稳定复现，这里用 mock 模拟
`createUser` 抛唯一索引冲突，断言它被转译成业务异常而不是原样冒出（mock 仅用于
制造竞态时序，断言落在真实的转译行为上）：

```java
package com.aventador.unifiedlogin.registration;

import com.aventador.unifiedlogin.user.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RegistrationServiceConcurrencyTest {

    @Test
    void translatesUniqueIndexViolationIntoEmailAlreadyRegistered() {
        UserService userService = mock(UserService.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        when(userService.emailExists(any())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("hash-value");
        when(userService.createUser(any(), anyString()))
                .thenThrow(new DataIntegrityViolationException("ux_app_user_email"));

        RegistrationService service = new RegistrationService(userService, passwordEncoder);

        assertThatThrownBy(() -> service.register("race@example.com", "a valid password"))
                .isInstanceOf(EmailAlreadyRegisteredException.class);
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=RegistrationServiceTest`
Expected: FAIL — 编译错误，`RegistrationService` 与 `EmailAlreadyRegisteredException` 尚不存在

- [ ] **Step 3: 写注册服务与异常**

`auth-server/src/main/java/com/aventador/unifiedlogin/registration/EmailAlreadyRegisteredException.java`

```java
package com.aventador.unifiedlogin.registration;

public class EmailAlreadyRegisteredException extends RuntimeException {

    public EmailAlreadyRegisteredException(String message) {
        super(message);
    }
}
```

`auth-server/src/main/java/com/aventador/unifiedlogin/registration/RegistrationService.java`

校验顺序为「邮箱格式 → 密码强度 → 邮箱查重」，保证密码不合规时不会产生任何写库动作。

两个有意的设计点：**register 不加 @Transactional**——Argon2 哈希耗时且吃 19MB 内存，不应
占着数据库连接与事务，唯一的写操作在 `UserService.createUser` 里自带事务；**catch
DataIntegrityViolationException 转译**——并发注册穿过查重时由唯一索引兜底，冲突异常在
掌握业务语义的这一层转译成「邮箱已被注册」，而不是以 500 冒给用户（Task 4 的 Javadoc
契约在此兑现）：

```java
package com.aventador.unifiedlogin.registration;

import com.aventador.unifiedlogin.password.PasswordPolicy;
import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.EmailAddress;
import com.aventador.unifiedlogin.user.UserService;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class RegistrationService {

    private static final String EMAIL_TAKEN_MESSAGE = "该邮箱已被注册";

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public RegistrationService(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    public AppUser register(String rawEmail, String rawPassword) {
        EmailAddress email = new EmailAddress(rawEmail);
        PasswordPolicy.validate(rawPassword);

        if (userService.emailExists(email)) {
            throw new EmailAlreadyRegisteredException(EMAIL_TAKEN_MESSAGE);
        }

        try {
            return userService.createUser(email, passwordEncoder.encode(rawPassword));
        }
        catch (DataIntegrityViolationException ex) {
            // 并发注册同一邮箱穿过了上面的查重，唯一索引兜底后在此转译
            throw new EmailAlreadyRegisteredException(EMAIL_TAKEN_MESSAGE);
        }
    }

    public boolean isEmailTaken(String rawEmail) {
        return userService.emailExists(new EmailAddress(rawEmail));
    }
}
```

同时把 `UserService.createUser` 的 `repository.save(user)` 改为 `repository.saveAndFlush(user)`，
并同步其 Javadoc（说明 saveAndFlush 保证冲突在调用点显现）——不立即 flush 时 INSERT 延迟到
事务提交，冲突异常在 catch 块之外才抛出，上面的转译就永远抓不住。

- [ ] **Step 4: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=RegistrationServiceTest,RegistrationServiceConcurrencyTest`
Expected: PASS，6 个测试全部通过（5 个集成 + 1 个并发转译单元测试）

- [ ] **Step 5: 写失败的控制器测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/web/RegistrationControllerTest.java`

```java
package com.aventador.unifiedlogin.web;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class RegistrationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Test
    void registrationPageIsPubliclyAccessible() throws Exception {
        mockMvc.perform(get("/register"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"));
    }

    @Test
    void successfulSubmissionCreatesUserAndRedirectsToLogin() throws Exception {
        mockMvc.perform(post("/register").with(csrf())
                        .param("email", "web-signup@example.com")
                        .param("password", "a valid password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?registered"));

        assertThat(registrationService.isEmailTaken("web-signup@example.com")).isTrue();
    }

    @Test
    void duplicateEmailRendersFormWithError() throws Exception {
        registrationService.register("taken@example.com", "a valid password");

        mockMvc.perform(post("/register").with(csrf())
                        .param("email", "taken@example.com")
                        .param("password", "a valid password"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"))
                .andExpect(model().attributeExists("errorMessage"));
    }

    @Test
    void invalidEmailRendersFormWithError() throws Exception {
        mockMvc.perform(post("/register").with(csrf())
                        .param("email", "not-an-email")
                        .param("password", "a valid password"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"))
                .andExpect(model().attributeExists("errorMessage"));
    }

    @Test
    void weakPasswordRendersFormWithError() throws Exception {
        mockMvc.perform(post("/register").with(csrf())
                        .param("email", "weak-web@example.com")
                        .param("password", "short"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"))
                .andExpect(model().attributeExists("errorMessage"));
    }

    @Test
    void submissionWithoutCsrfTokenIsRejected() throws Exception {
        mockMvc.perform(post("/register")
                        .param("email", "no-csrf@example.com")
                        .param("password", "a valid password"))
                .andExpect(status().isForbidden());
    }
}
```

- [ ] **Step 6: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=RegistrationControllerTest`
Expected: FAIL — `/register` 返回 401 或 404（尚无控制器，且默认安全策略拦截全部请求）

- [ ] **Step 7: 写控制器**

`auth-server/src/main/java/com/aventador/unifiedlogin/web/RegistrationController.java`

控制器用 `@RequestParam` 直接收两个字段，不引入表单对象——两个参数不值得一个 record，
等字段多到需要绑定校验时再建（YAGNI）。

三类校验异常统一转成页面上的错误提示，且失败时把邮箱回填，避免用户重填：

```java
package com.aventador.unifiedlogin.web;

import com.aventador.unifiedlogin.password.WeakPasswordException;
import com.aventador.unifiedlogin.registration.EmailAlreadyRegisteredException;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.user.InvalidEmailException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class RegistrationController {

    private final RegistrationService registrationService;

    public RegistrationController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @GetMapping("/register")
    public String showRegistrationPage() {
        return "register";
    }

    @PostMapping("/register")
    public String submitRegistration(@RequestParam String email,
                                     @RequestParam String password,
                                     Model model) {
        try {
            registrationService.register(email, password);
            return "redirect:/login?registered";
        }
        catch (InvalidEmailException | WeakPasswordException | EmailAlreadyRegisteredException ex) {
            model.addAttribute("errorMessage", ex.getMessage());
            model.addAttribute("email", email);
            return "register";
        }
    }
}
```

- [ ] **Step 8: 写注册页模板**

`auth-server/src/main/resources/templates/register.html`

```html
<!DOCTYPE html>
<html lang="zh-CN" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>注册</title>
</head>
<body>
<main>
    <h1>注册</h1>

    <p th:if="${errorMessage}" th:text="${errorMessage}" data-testid="register-error"></p>

    <form method="post" th:action="@{/register}">
        <label for="email">邮箱</label>
        <input type="email" id="email" name="email" th:value="${email}" required autocomplete="email">

        <label for="password">密码</label>
        <input type="password" id="password" name="password" required autocomplete="new-password"
               minlength="8" maxlength="64">

        <button type="submit">注册</button>
    </form>

    <p><a th:href="@{/login}">已有账号，去登录</a></p>
</main>
</body>
</html>
```

- [ ] **Step 9: 写安全配置放行注册页**

`auth-server/src/main/java/com/aventador/unifiedlogin/config/SecurityConfig.java`

本任务只需一条过滤链，Task 6 与 Task 8 会在此文件上继续扩展：

```java
package com.aventador.unifiedlogin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        // /error 必须放行：Spring Security 7 默认拦截 ERROR dispatch，
                        // 不放行时未捕获异常的错误页转发会被再拦一次，500 都呈现不出来
                        .requestMatchers("/register", "/error").permitAll()
                        .anyRequest().authenticated());

        return http.build();
    }
}
```

- [ ] **Step 10: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=RegistrationControllerTest`
Expected: PASS，6 个测试全部通过

- [ ] **Step 11: 运行全部测试并提交**

Run: `cd auth-server && ./mvnw test`
Expected: 至此所有测试类全部通过

```bash
git add auth-server/src
git commit -m "feat(registration): 新增邮箱注册功能与注册页

注册时先校验邮箱格式与密码强度再查重，密码以哈希形式落库；
页面对格式错误、弱密码与重复邮箱给出提示并回填邮箱。"
```

---

### Task 6: 登录与账号状态校验

**Files:**
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/security/AppUserDetailsService.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/web/LoginController.java`
- Create: `auth-server/src/main/resources/templates/login.html`
- Modify: `auth-server/src/main/java/com/aventador/unifiedlogin/config/SecurityConfig.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/security/AppUserDetailsServiceTest.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/web/LoginFlowTest.java`

**Interfaces:**
- Consumes: `UserService`、`RegistrationService`、`SecurityConfig`
- Produces: `AppUserDetailsService`（实现 `UserDetailsService`，`UserDetails.getUsername()` 返回邮箱）；登录页路由 `/login`

**关于 JWT 的 sub**：本任务让 `UserDetails.getUsername()` 返回邮箱，这是表单登录所必需的。但它会导致 JWT 的 `sub` 被签成邮箱，与规格书 §6.4 要求的「`sub` 为用户 UUID」不符。**Task 9 专门负责纠正这一点，本任务不处理，也不要为此改动此处返回值**——若在这里返回 UUID，登录表单将无法按邮箱查到用户。

**关于防邮箱枚举**：`DaoAuthenticationProvider` 内置了针对计时攻击的缓解——用户不存在时它仍会对一个占位密码执行一次 `PasswordEncoder.matches`。因此**不要自行实现耗时对齐逻辑**，只需保证使用标准的 `UserDetailsService` + `PasswordEncoder` 装配即可。测试断言的是「两种失败返回相同结果」，不做时间断言（时间断言必然不稳定）。

- [ ] **Step 1: 写失败的 UserDetailsService 测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/security/AppUserDetailsServiceTest.java`

```java
package com.aventador.unifiedlogin.security;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@Import(PostgresTestConfig.class)
class AppUserDetailsServiceTest {

    @Autowired
    private AppUserDetailsService userDetailsService;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void loadsUserByEmail() {
        registrationService.register("details@example.com", "a valid password");

        UserDetails details = userDetailsService.loadUserByUsername("details@example.com");

        assertThat(details.getUsername()).isEqualTo("details@example.com");
        assertThat(details.isEnabled()).isTrue();
    }

    @Test
    void loadsUserIgnoringInputCase() {
        registrationService.register("case-details@example.com", "a valid password");

        UserDetails details = userDetailsService.loadUserByUsername("Case-Details@Example.COM");

        assertThat(details.getUsername()).isEqualTo("case-details@example.com");
    }

    @Test
    void disabledUserIsMappedAsDisabled() {
        registrationService.register("disabled-details@example.com", "a valid password");
        // 领域模型尚无禁用入口（管理后台在后续阶段），测试用 SQL 直接翻转状态，不新增生产代码
        jdbcTemplate.update("UPDATE app_user SET status = 'DISABLED' WHERE email = ?",
                "disabled-details@example.com");

        UserDetails details = userDetailsService.loadUserByUsername("disabled-details@example.com");

        assertThat(details.isEnabled()).isFalse();
    }

    @Test
    void throwsForUnknownEmail() {
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("nobody@example.com"))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void throwsForMalformedEmailInsteadOfLeakingParseError() {
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("not-an-email"))
                .isInstanceOf(UsernameNotFoundException.class);
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=AppUserDetailsServiceTest`
Expected: FAIL — 编译错误，`AppUserDetailsService` 尚不存在

- [ ] **Step 3: 写 AppUserDetailsService**

`auth-server/src/main/java/com/aventador/unifiedlogin/security/AppUserDetailsService.java`

非法格式的邮箱同样抛 `UsernameNotFoundException`，使「格式错误」与「账号不存在」对外表现一致：

```java
package com.aventador.unifiedlogin.security;

import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.EmailAddress;
import com.aventador.unifiedlogin.user.InvalidEmailException;
import com.aventador.unifiedlogin.user.UserService;
import com.aventador.unifiedlogin.user.UserStatus;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class AppUserDetailsService implements UserDetailsService {

    private static final String NOT_FOUND_MESSAGE = "邮箱或密码不正确";

    private final UserService userService;

    public AppUserDetailsService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        EmailAddress email;
        try {
            email = new EmailAddress(username);
        }
        catch (InvalidEmailException ex) {
            throw new UsernameNotFoundException(NOT_FOUND_MESSAGE);
        }

        AppUser user = userService.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(NOT_FOUND_MESSAGE));

        return User.withUsername(user.getEmail())
                .password(user.getPasswordHash())
                .disabled(user.getStatus() == UserStatus.DISABLED)
                .authorities(Collections.emptyList())
                .build();
    }
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=AppUserDetailsServiceTest`
Expected: PASS，5 个测试全部通过

- [ ] **Step 5: 写失败的登录流程测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/web/LoginFlowTest.java`

```java
package com.aventador.unifiedlogin.web;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class LoginFlowTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void loginPageIsPubliclyAccessible() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
    }

    @Test
    void correctCredentialsAuthenticate() throws Exception {
        registrationService.register("login-ok@example.com", "a valid password");

        mockMvc.perform(formLogin("/login").user("login-ok@example.com").password("a valid password"))
                .andExpect(authenticated());
    }

    @Test
    void emailCaseIsIgnoredOnLogin() throws Exception {
        registrationService.register("login-case@example.com", "a valid password");

        mockMvc.perform(formLogin("/login").user("Login-Case@Example.COM").password("a valid password"))
                .andExpect(authenticated());
    }

    @Test
    void wrongPasswordFailsWithGenericRedirect() throws Exception {
        registrationService.register("login-bad@example.com", "a valid password");

        mockMvc.perform(formLogin("/login").user("login-bad@example.com").password("wrong password"))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void unknownEmailFailsIdenticallyToWrongPassword() throws Exception {
        mockMvc.perform(formLogin("/login").user("ghost@example.com").password("a valid password"))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void disabledAccountFailsIdenticallyToWrongPassword() throws Exception {
        String email = "login-disabled@example.com";
        registrationService.register(email, "a valid password");
        jdbcTemplate.update("UPDATE app_user SET status = 'DISABLED' WHERE email = ?", email);

        // 密码正确但账号被禁用：对外表现必须与密码错误完全一致，否则泄漏「账号存在但被禁用」
        mockMvc.perform(formLogin("/login").user(email).password("a valid password"))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void protectedPageRedirectsToLoginWhenAnonymous() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }
}
```

- [ ] **Step 6: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=LoginFlowTest`
Expected: FAIL — `/login` 无对应视图，表单登录未启用

- [ ] **Step 7: 写登录控制器与页面**

`auth-server/src/main/java/com/aventador/unifiedlogin/web/LoginController.java`

```java
package com.aventador.unifiedlogin.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String showLoginPage() {
        return "login";
    }
}
```

`auth-server/src/main/resources/templates/login.html`

```html
<!DOCTYPE html>
<html lang="zh-CN" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>登录</title>
</head>
<body>
<main>
    <h1>登录</h1>

    <p th:if="${param.error}" data-testid="login-error">邮箱或密码不正确</p>
    <p th:if="${param.registered}" data-testid="login-registered">注册成功，请登录</p>

    <form method="post" th:action="@{/login}">
        <label for="username">邮箱</label>
        <input type="email" id="username" name="username" required autocomplete="email">

        <label for="password">密码</label>
        <input type="password" id="password" name="password" required autocomplete="current-password">

        <button type="submit">登录</button>
    </form>

    <p><a th:href="@{/register}">还没有账号，去注册</a></p>
</main>
</body>
</html>
```

- [ ] **Step 8: 修改 SecurityConfig 启用表单登录**

`auth-server/src/main/java/com/aventador/unifiedlogin/config/SecurityConfig.java` 整体替换为：

```java
package com.aventador.unifiedlogin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        // /error 必须放行：Spring Security 7 默认拦截 ERROR dispatch，
                        // 不放行时未捕获异常的错误页转发会被再拦一次，500 都呈现不出来
                        .requestMatchers("/register", "/login", "/error").permitAll()
                        .anyRequest().authenticated())
                .formLogin((formLogin) -> formLogin
                        // 必须指定自定义登录页：默认配置会启用登录页生成过滤器，遮蔽 Thymeleaf 模板
                        .loginPage("/login"));

        return http.build();
    }
}
```

- [ ] **Step 9: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=LoginFlowTest`
Expected: PASS，7 个测试全部通过

- [ ] **Step 10: 提交**

```bash
git add auth-server/src
git commit -m "feat(login): 新增登录页与账号状态校验

登录忽略邮箱大小写，账号不存在与密码错误返回完全一致的结果，
被禁用的账号无法登录。"
```

---

### Task 7: 授权服务器数据表与产品客户端配置同步

**Files:**
- Create: `auth-server/src/main/resources/db/migration/V2__oauth2_server_tables.sql`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/config/UnifiedLoginProperties.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/config/ClientSyncRunner.java`
- Modify: `auth-server/src/main/resources/application.yml`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/config/ClientSyncRunnerTest.java`

**Interfaces:**
- Consumes: `PostgresTestConfig`
- Produces:
  - 表 `oauth2_registered_client`、`oauth2_authorization`、`oauth2_authorization_consent`
  - `UnifiedLoginProperties`（`clients()` 返回 `List<ClientConfig>`，`ClientConfig` 含 `clientId()`、`clientName()`、`redirectUris()`）
  - Spring 容器中的 `RegisteredClientRepository`（`JdbcRegisteredClientRepository` 实例）

**关于 DDL**：以下建表语句取自框架 jar 内的官方 schema，并按其头部注释要求做了 PostgreSQL 适配——**所有 `blob` 改为 `text`，所有 `timestamp` 改为 `timestamptz`**。不要直接复制框架原文件。

- [ ] **Step 1: 写失败的测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/config/ClientSyncRunnerTest.java`

```java
package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Import(PostgresTestConfig.class)
class ClientSyncRunnerTest {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    @Qualifier("syncRegisteredClients")
    private ApplicationRunner syncRunner;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void demoWebAIsRegisteredFromConfiguration() {
        RegisteredClient client = registeredClientRepository.findByClientId("demo-web-a");

        assertThat(client).isNotNull();
        assertThat(client.getRedirectUris()).contains("http://localhost:5173/callback");
    }

    @Test
    void clientIsPublicAndRequiresPkce() {
        RegisteredClient client = registeredClientRepository.findByClientId("demo-web-a");

        assertThat(client.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getClientSettings().isRequireAuthorizationConsent()).isFalse();
    }

    @Test
    void clientSupportsAuthorizationCodeAndRefreshTokenOnly() {
        RegisteredClient client = registeredClientRepository.findByClientId("demo-web-a");

        assertThat(client.getAuthorizationGrantTypes())
                .containsExactlyInAnyOrder(AuthorizationGrantType.AUTHORIZATION_CODE,
                        AuthorizationGrantType.REFRESH_TOKEN);
    }

    @Test
    void tokenLifetimesMatchSpecification() {
        RegisteredClient client = registeredClientRepository.findByClientId("demo-web-a");

        assertThat(client.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(15));
        assertThat(client.getTokenSettings().getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(30));
        assertThat(client.getTokenSettings().isReuseRefreshTokens()).isFalse();
    }

    @Test
    void unknownClientIsNotRegistered() {
        assertThat(registeredClientRepository.findByClientId("never-configured")).isNull();
    }

    @Test
    void syncIsIdempotentAcrossRestarts() throws Exception {
        RegisteredClient before = registeredClientRepository.findByClientId("demo-web-a");

        // 手动再执行一次启动同步，模拟应用重启（上下文缓存不会自动重跑 ApplicationRunner）
        syncRunner.run(null);

        RegisteredClient after = registeredClientRepository.findByClientId("demo-web-a");
        assertThat(after.getId()).isEqualTo(before.getId());
        assertThat(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM oauth2_registered_client WHERE client_id = 'demo-web-a'",
                Integer.class)).isEqualTo(1);
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=ClientSyncRunnerTest`
Expected: FAIL — 容器中没有 `RegisteredClientRepository` Bean，或 `oauth2_registered_client` 表不存在

- [ ] **Step 3: 写 V2 迁移脚本**

`auth-server/src/main/resources/db/migration/V2__oauth2_server_tables.sql`

```sql
CREATE TABLE oauth2_registered_client (
    id                            varchar(100)  NOT NULL,
    client_id                     varchar(100)  NOT NULL,
    client_id_issued_at           timestamptz   DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret                 varchar(200)  DEFAULT NULL,
    client_secret_expires_at      timestamptz   DEFAULT NULL,
    client_name                   varchar(200)  NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types     varchar(1000) NOT NULL,
    redirect_uris                 varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris     varchar(1000) DEFAULT NULL,
    scopes                        varchar(1000) NOT NULL,
    client_settings               varchar(2000) NOT NULL,
    token_settings                varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization (
    id                            varchar(100)  NOT NULL,
    registered_client_id          varchar(100)  NOT NULL,
    principal_name                varchar(200)  NOT NULL,
    authorization_grant_type      varchar(100)  NOT NULL,
    authorized_scopes             varchar(1000) DEFAULT NULL,
    attributes                    text          DEFAULT NULL,
    state                         varchar(500)  DEFAULT NULL,
    authorization_code_value      text          DEFAULT NULL,
    authorization_code_issued_at  timestamptz   DEFAULT NULL,
    authorization_code_expires_at timestamptz   DEFAULT NULL,
    authorization_code_metadata   text          DEFAULT NULL,
    access_token_value            text          DEFAULT NULL,
    access_token_issued_at        timestamptz   DEFAULT NULL,
    access_token_expires_at       timestamptz   DEFAULT NULL,
    access_token_metadata         text          DEFAULT NULL,
    access_token_type             varchar(100)  DEFAULT NULL,
    access_token_scopes           varchar(1000) DEFAULT NULL,
    oidc_id_token_value           text          DEFAULT NULL,
    oidc_id_token_issued_at       timestamptz   DEFAULT NULL,
    oidc_id_token_expires_at      timestamptz   DEFAULT NULL,
    oidc_id_token_metadata        text          DEFAULT NULL,
    refresh_token_value           text          DEFAULT NULL,
    refresh_token_issued_at       timestamptz   DEFAULT NULL,
    refresh_token_expires_at      timestamptz   DEFAULT NULL,
    refresh_token_metadata        text          DEFAULT NULL,
    user_code_value               text          DEFAULT NULL,
    user_code_issued_at           timestamptz   DEFAULT NULL,
    user_code_expires_at          timestamptz   DEFAULT NULL,
    user_code_metadata            text          DEFAULT NULL,
    device_code_value             text          DEFAULT NULL,
    device_code_issued_at         timestamptz   DEFAULT NULL,
    device_code_expires_at        timestamptz   DEFAULT NULL,
    device_code_metadata          text          DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization_consent (
    registered_client_id varchar(100)  NOT NULL,
    principal_name       varchar(200)  NOT NULL,
    authorities          varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);
```

- [ ] **Step 4: 在 application.yml 追加 client 配置**

在 `auth-server/src/main/resources/application.yml` 末尾追加：

```yaml
unified-login:
  clients:
    - client-id: demo-web-a
      client-name: Demo Web A
      redirect-uris:
        - http://localhost:5173/callback
```

- [ ] **Step 5: 写配置绑定类**

`auth-server/src/main/java/com/aventador/unifiedlogin/config/UnifiedLoginProperties.java`

```java
package com.aventador.unifiedlogin.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "unified-login")
public record UnifiedLoginProperties(List<ClientConfig> clients) {

    public record ClientConfig(String clientId, String clientName, List<String> redirectUris) {
    }
}
```

- [ ] **Step 6: 写客户端同步器**

`auth-server/src/main/java/com/aventador/unifiedlogin/config/ClientSyncRunner.java`

关键点：`JdbcRegisteredClientRepository.save` 以 `id` 为主键做更新，因此已存在的 client 必须沿用其原有 `id` 重建，否则会因 `client_id` 重复而插入失败：

```java
package com.aventador.unifiedlogin.config;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Configuration
@EnableConfigurationProperties(UnifiedLoginProperties.class)
public class ClientSyncRunner {

    private static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(15);
    private static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(30);

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /**
     * 幂等同步：已存在的 client 沿用原 id 重建后 save（save 以 id 为主键更新）。
     * 注意：配置中移除某个 client 不会删除库中已注册的行及其回调白名单，
     * 需手动清理——与 bootstrap.admin-emails 的撤销语义一致。
     */
    @Bean
    public ApplicationRunner syncRegisteredClients(RegisteredClientRepository repository,
                                                   UnifiedLoginProperties properties) {
        return (args) -> {
            // record 构造器绑定在配置节点缺失时得到 null 而非空列表，这里显式归一
            List<UnifiedLoginProperties.ClientConfig> clients =
                    Objects.requireNonNullElseGet(properties.clients(), List::of);
            for (UnifiedLoginProperties.ClientConfig config : clients) {
                RegisteredClient existing = repository.findByClientId(config.clientId());
                String id = (existing != null) ? existing.getId() : UUID.randomUUID().toString();
                repository.save(build(id, config));
            }
        };
    }

    private static RegisteredClient build(String id, UnifiedLoginProperties.ClientConfig config) {
        RegisteredClient.Builder builder = RegisteredClient.withId(id)
                .clientId(config.clientId())
                .clientName(config.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(ACCESS_TOKEN_TTL)
                        .refreshTokenTimeToLive(REFRESH_TOKEN_TTL)
                        .reuseRefreshTokens(false)
                        .build());

        List<String> redirectUris = config.redirectUris();
        if (redirectUris == null || redirectUris.isEmpty()) {
            throw new IllegalStateException("客户端 " + config.clientId() + " 未配置 redirect-uris，回调白名单不能为空");
        }
        redirectUris.forEach(builder::redirectUri);

        return builder.build();
    }
}
```

- [ ] **Step 7: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=ClientSyncRunnerTest`
Expected: PASS，6 个测试全部通过

- [ ] **Step 8: 幂等性由 syncIsIdempotentAcrossRestarts 用例直接验证**

该用例手动第二次执行同步 Runner，断言同一 client_id 的 id 不变且表中仅一行。
（注意：`-Dsurefire.rerunFailingTestsCount` **不能**用于验证幂等——它只在测试失败时重跑，
且 Spring 上下文缓存下 ApplicationRunner 不会随重跑再次执行。）

- [ ] **Step 9: 提交**

```bash
git add auth-server/src
git commit -m "feat(config): 建立授权服务器数据表并同步产品客户端配置

按 PostgreSQL 要求适配官方建表语句，启动时把配置文件中的产品
客户端幂等同步入库，统一设定为公开客户端、强制 PKCE、跳过同意页。"
```

---

### Task 8: 授权服务器配置与 RSA 密钥持久化

**Files:**
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/config/RsaKeyProvider.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/config/AuthorizationServerConfig.java`
- Modify: `auth-server/src/main/java/com/aventador/unifiedlogin/config/SecurityConfig.java`
- Modify: `auth-server/src/main/resources/application.yml`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/config/RsaKeyProviderTest.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/config/OidcEndpointsTest.java`

**Interfaces:**
- Consumes: `SecurityConfig`（Task 6）、`RegisteredClientRepository`（Task 7）
- Produces: `RsaKeyProvider.loadOrCreate(Path): RSAKey`（静态方法）、`JWKSource<SecurityContext>` Bean、`AuthorizationServerSettings` Bean、授权服务器过滤链

- [ ] **Step 1: 写失败的密钥持久化测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/config/RsaKeyProviderTest.java`

```java
package com.aventador.unifiedlogin.config;

import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class RsaKeyProviderTest {

    @Test
    void createsKeyFileWhenAbsent(@TempDir Path tempDir) throws Exception {
        Path keyFile = tempDir.resolve("jwt-signing-key.json");

        RSAKey key = RsaKeyProvider.loadOrCreate(keyFile);

        assertThat(Files.exists(keyFile)).isTrue();
        assertThat(key.getKeyID()).isNotBlank();
        assertThat(key.toRSAPrivateKey()).isNotNull();
    }

    @Test
    void reusesSameKeyAcrossRestarts(@TempDir Path tempDir) throws Exception {
        Path keyFile = tempDir.resolve("jwt-signing-key.json");

        RSAKey first = RsaKeyProvider.loadOrCreate(keyFile);
        RSAKey second = RsaKeyProvider.loadOrCreate(keyFile);

        assertThat(second.getKeyID()).isEqualTo(first.getKeyID());
        assertThat(second.toRSAPublicKey().getModulus()).isEqualTo(first.toRSAPublicKey().getModulus());
    }

    @Test
    void createsParentDirectoriesWhenMissing(@TempDir Path tempDir) throws Exception {
        Path keyFile = tempDir.resolve("nested/deeper/jwt-signing-key.json");

        RsaKeyProvider.loadOrCreate(keyFile);

        assertThat(Files.exists(keyFile)).isTrue();
    }

    @Test
    void keyFileIsReadableOnlyByOwner(@TempDir Path tempDir) throws Exception {
        // 文件内容是签名私钥，其他本地用户不得可读
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));

        Path keyFile = tempDir.resolve("jwt-signing-key.json");
        RsaKeyProvider.loadOrCreate(keyFile);

        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(keyFile)))
                .isEqualTo("rw-------");
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=RsaKeyProviderTest`
Expected: FAIL — 编译错误，`RsaKeyProvider` 尚不存在

- [ ] **Step 3: 写 RsaKeyProvider**

`auth-server/src/main/java/com/aventador/unifiedlogin/config/RsaKeyProvider.java`

密钥以 JWK 的 JSON 形式落盘，避免自行处理 PEM 编解码：

```java
package com.aventador.unifiedlogin.config;

import com.nimbusds.jose.jwk.RSAKey;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.UUID;

public final class RsaKeyProvider {

    private static final int KEY_SIZE = 2048;
    private static final String OWNER_ONLY_PERMISSIONS = "rw-------";

    private RsaKeyProvider() {
    }

    public static RSAKey loadOrCreate(Path keyFile) {
        try {
            if (Files.exists(keyFile)) {
                return RSAKey.parse(Files.readString(keyFile, StandardCharsets.UTF_8));
            }

            RSAKey generated = generate();
            Path absolute = keyFile.toAbsolutePath();
            Files.createDirectories(absolute.getParent());
            writeOwnerOnlyAtomically(absolute, generated.toJSONString());
            return generated;
        }
        catch (IOException ex) {
            throw new UncheckedIOException("无法读写 JWT 签名密钥文件：" + keyFile, ex);
        }
        catch (ParseException ex) {
            throw new IllegalStateException("JWT 签名密钥文件内容无法解析：" + keyFile, ex);
        }
    }

    /**
     * 先写临时文件再原子改名：中途崩溃不会留下半截密钥文件——那会让下次启动
     * 因解析失败而永久起不来。文件权限收紧为仅属主可读写：内容是签名私钥，
     * 其他本地用户不得可读。
     */
    private static void writeOwnerOnlyAtomically(Path keyFile, String content) throws IOException {
        Path tmp;
        try {
            tmp = Files.createTempFile(keyFile.getParent(), keyFile.getFileName().toString(), ".tmp",
                    PosixFilePermissions.asFileAttribute(
                            PosixFilePermissions.fromString(OWNER_ONLY_PERMISSIONS)));
        }
        catch (UnsupportedOperationException ex) {
            // 非 POSIX 文件系统（如 Windows NTFS）不支持该属性，退化为默认权限
            tmp = Files.createTempFile(keyFile.getParent(), keyFile.getFileName().toString(), ".tmp");
        }
        try {
            Files.writeString(tmp, content, StandardCharsets.UTF_8);
            Files.move(tmp, keyFile, StandardCopyOption.ATOMIC_MOVE);
        }
        catch (IOException ex) {
            Files.deleteIfExists(tmp);
            throw ex;
        }
    }

    private static RSAKey generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(KEY_SIZE);
            KeyPair keyPair = generator.generateKeyPair();

            return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .build();
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("当前 JVM 不支持 RSA 密钥生成", ex);
        }
    }
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=RsaKeyProviderTest`
Expected: PASS，4 个测试全部通过

- [ ] **Step 5: 写失败的 OIDC 端点测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/config/OidcEndpointsTest.java`

```java
package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class OidcEndpointsTest {

    // 密钥路径的隔离由 PostgresTestConfig 统一提供（所有加载上下文的测试共用），
    // 不在此单点覆盖——否则其他测试类仍会在项目目录里生成真实私钥
    @Autowired
    private MockMvc mockMvc;

    @Test
    void discoveryDocumentIsPubliclyAvailable() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").exists())
                .andExpect(jsonPath("$.authorization_endpoint").exists())
                .andExpect(jsonPath("$.token_endpoint").exists())
                .andExpect(jsonPath("$.jwks_uri").exists())
                .andExpect(jsonPath("$.userinfo_endpoint").exists());
    }

    @Test
    void discoveryAdvertisesAuthorizationCodeAndRefreshTokenGrants() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.grant_types_supported").value(
                        org.hamcrest.Matchers.hasItems("authorization_code", "refresh_token")));
    }

    @Test
    void jwksEndpointExposesPublicKeyWithoutPrivateMaterial() throws Exception {
        // RSA 私钥在 JWK 里共六个字段，漏断言任何一个都可能放过泄漏
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].n").exists())
                .andExpect(jsonPath("$.keys[0].kid").exists())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())
                .andExpect(jsonPath("$.keys[0].q").doesNotExist())
                .andExpect(jsonPath("$.keys[0].dp").doesNotExist())
                .andExpect(jsonPath("$.keys[0].dq").doesNotExist())
                .andExpect(jsonPath("$.keys[0].qi").doesNotExist());
    }

    @Test
    void userinfoWithoutTokenReturnsUnauthorized() throws Exception {
        // 401 + Bearer 挑战头证明资源服务器过滤器已接上；配置缺失时这里会是 403 或 302
        mockMvc.perform(get("/userinfo").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", startsWith("Bearer")));
    }

    @Test
    void authorizationEndpointRedirectsAnonymousUserToLogin() throws Exception {
        // 参数必须写进 query string：框架用 request.getQueryString() 过滤授权参数，
        // 而 MockMvc 的 .param() 不填充 queryString，参数会被整批丢弃报 invalid_request
        mockMvc.perform(get("/oauth2/authorize"
                        + "?response_type=code"
                        + "&client_id=demo-web-a"
                        + "&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fcallback"
                        + "&scope=openid"
                        + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
                        + "&code_challenge_method=S256"))
                .andExpect(status().is3xxRedirection());
    }
}
```

- [ ] **Step 6: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=OidcEndpointsTest`
Expected: FAIL — 授权服务器过滤链未配置，`/.well-known/openid-configuration` 返回 401 或 404

- [ ] **Step 7: 在 application.yml 追加密钥路径配置**

在 `unified-login:` 节点下追加（与 `clients` 同级）：

```yaml
unified-login:
  issuer: ${ISSUER_URL:http://localhost:9000}
  jwt-key-store: ${JWT_KEY_STORE:./data/jwt-signing-key.json}
  clients:
    - client-id: demo-web-a
      client-name: Demo Web A
      redirect-uris:
        - http://localhost:5173/callback
```

- [ ] **Step 8: 更新配置绑定类**

`auth-server/src/main/java/com/aventador/unifiedlogin/config/UnifiedLoginProperties.java` 整体替换为：

```java
package com.aventador.unifiedlogin.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "unified-login")
public record UnifiedLoginProperties(String issuer, String jwtKeyStore, List<ClientConfig> clients) {

    public record ClientConfig(String clientId, String clientName, List<String> redirectUris) {
    }
}
```

- [ ] **Step 9: 写授权服务器配置**

`auth-server/src/main/java/com/aventador/unifiedlogin/config/AuthorizationServerConfig.java`

注意两个配置类的 import 路径——这是 Spring Security 7 的新位置，用旧路径会编译失败：

```java
package com.aventador.unifiedlogin.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.file.Path;
import java.util.Objects;

@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Spring Security 7 中该类没有 authorizationServer() 静态工厂（那是旧 1.x 的 API），
        // 用无参构造——照旧文档写静态工厂会编译失败
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer.oidc(Customizer.withDefaults()))
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated())
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                // 必需：/userinfo 端点自身不解析 Bearer token，靠资源服务器过滤器
                // 先完成认证。缺这一句该端点对任何合法 token 都返回拒绝
                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
                                                           RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(UnifiedLoginProperties properties) {
        String keyStore = Objects.requireNonNull(properties.jwtKeyStore(),
                "unified-login.jwt-key-store 未配置");
        RSAKey rsaKey = RsaKeyProvider.loadOrCreate(Path.of(keyStore));
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(UnifiedLoginProperties properties) {
        // issuer 必须来自配置（ISSUER_URL）：写死在代码里的话，部署到任何非本地
        // 环境都会在 discovery 与 JWT 的 iss 里广播错误地址
        return AuthorizationServerSettings.builder()
                .issuer(Objects.requireNonNull(properties.issuer(), "unified-login.issuer 未配置"))
                .build();
    }
}
```

- [ ] **Step 10: 调整 SecurityConfig 的过滤链顺序**

`auth-server/src/main/java/com/aventador/unifiedlogin/config/SecurityConfig.java` 整体替换为——授权服务器链为 `@Order(1)`，默认链必须排在其后：

```java
package com.aventador.unifiedlogin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        // /error 必须放行：Spring Security 7 默认拦截 ERROR dispatch，
                        // 不放行时未捕获异常的错误页转发会被再拦一次，500 都呈现不出来
                        .requestMatchers("/register", "/login", "/error").permitAll()
                        .anyRequest().authenticated())
                .formLogin((formLogin) -> formLogin
                        // 必须指定自定义登录页：默认配置会启用登录页生成过滤器，遮蔽 Thymeleaf 模板
                        .loginPage("/login"));

        return http.build();
    }
}
```

- [ ] **Step 11: 把密钥文件目录加入 .gitignore**

在项目根 `.gitignore` 追加：

```
data/
```

- [ ] **Step 12: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=OidcEndpointsTest`
Expected: PASS，5 个测试全部通过

- [ ] **Step 13: 运行全部测试并提交**

Run: `cd auth-server && ./mvnw test`
Expected: 所有测试类全部通过

```bash
git add auth-server/src .gitignore
git commit -m "feat(config): 启用 OIDC 协议端点并持久化签名密钥

签名密钥首次启动时生成并落盘，重启后复用，避免重启导致已签发的
令牌全部失效；授权服务器过滤链优先于默认链处理协议端点请求。"
```

---

### Task 9: JWT 载荷定制（sub 为用户 ID，附带 email）

**Files:**
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/config/JwtClaimsConfig.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/support/OAuth2TestFlows.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/config/JwtClaimsConfigTest.java`

**Interfaces:**
- Consumes: `UserService`、`EmailAddress`、`AuthorizationServerConfig`（Task 8）
- Produces:
  - `OAuth2TokenCustomizer<JwtEncodingContext>` Bean。定制后 access token 与 id token 的 `sub` 均为 `app_user.id` 的字符串形式，并额外携带 `email` claim
  - `OAuth2TestFlows`：测试辅助类，供本任务与 Task 10 共用。静态常量 `CLIENT_ID`、`REDIRECT_URI`、`CODE_VERIFIER`、`CODE_CHALLENGE`；静态方法 `authorizeAndExtractCode(MockMvc, String userEmail): String`、`exchangeCode(MockMvc, String code): String`（返回令牌响应的 JSON 原文）、`jsonField(String json, String field): String`

**为什么必须在阶段一做**：各产品后端将用 `sub` 作为外键关联本地业务数据。若阶段一签发的 `sub` 是邮箱，后续改成 UUID 就是破坏性变更——产品库里已存的关联全部失效，且用户改邮箱会导致身份漂移。UUID 永不变，邮箱会变，所以 `sub` 必须是 UUID。

- [ ] **Step 1: 写共用的测试辅助类**

`auth-server/src/test/java/com/aventador/unifiedlogin/support/OAuth2TestFlows.java`

这是测试基础设施而非生产代码，Task 10 会复用它，因此先建立。PKCE 测试向量取自 RFC 7636 附录 B，固定值避免每次运行重新计算：

```java
package com.aventador.unifiedlogin.support;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public final class OAuth2TestFlows {

    public static final String CLIENT_ID = "demo-web-a";
    public static final String REDIRECT_URI = "http://localhost:5173/callback";
    public static final String CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    public static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private OAuth2TestFlows() {
    }

    /**
     * 构造授权端点 URI。**参数必须放在 query string 里**：框架用
     * request.getQueryString() 过滤授权参数，而 MockMvc 的 .param() 不填充 queryString，
     * 用 .param() 会让参数被整批丢弃、端点报 invalid_request。
     */
    public static String authorizeUri(Map<String, String> params) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromPath("/oauth2/authorize");
        params.forEach(builder::queryParam);
        // 必须 encode()：Task 10 会构造含特殊字符的非法参数来测边界，
        // 不编码时这些字符会破坏查询串结构，失败现象与测试意图无关、极难排查
        return builder.build().encode().toString();
    }

    /** 标准的合法授权请求参数（可按需覆盖或删改某项来构造异常场景）。 */
    public static Map<String, String> validAuthorizeParams() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("scope", "openid");
        params.put("code_challenge", CODE_CHALLENGE);
        params.put("code_challenge_method", "S256");
        return params;
    }

    /**
     * 走真实表单登录并返回会话。
     *
     * **不能用 `.with(user(...))` 替代**：那样造出的主体缺少 Spring Security 7 的
     * FactorGrantedAuthority，而框架签发 token 时要从它推导认证时间，
     * 会抛 "authenticationTime cannot be null"。必须走真实登录链路。
     */
    public static MockHttpSession login(MockMvc mockMvc, String email, String rawPassword) throws Exception {
        MvcResult result = mockMvc.perform(formLogin("/login").user(email).password(rawPassword))
                .andExpect(authenticated())
                .andReturn();

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        assertThat(session).as("登录后应存在会话").isNotNull();
        return session;
    }

    /** 以已登录会话走一次授权端点，返回回调地址中的一次性授权码。 */
    public static String authorizeAndExtractCode(MockMvc mockMvc, MockHttpSession session) throws Exception {
        MvcResult result = mockMvc.perform(get(authorizeUri(validAuthorizeParams()))
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String location = result.getResponse().getRedirectedUrl();
        assertThat(location).startsWith(REDIRECT_URI);

        return queryParam(location, "code");
    }

    /** 用授权码换取令牌，返回响应 JSON 原文。仅用于预期成功的场景。 */
    public static String exchangeCode(MockMvc mockMvc, String code) throws Exception {
        return mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
    }

    /**
     * 从令牌响应中取出某个字段的值。用 Jackson 而非字符串查找：
     * 后者只能取带引号的字符串字段，遇到数字/布尔字段会误报「字段不存在」，
     * 把后续任务的排查方向带偏。
     */
    public static String jsonField(String json, String field) {
        try {
            JsonNode node = OBJECT_MAPPER.readTree(json).path(field);
            assertThat(node.isMissingNode()).as("响应中应包含字段 %s", field).isFalse();
            return node.asText();
        }
        catch (JsonProcessingException ex) {
            throw new AssertionError("令牌响应不是合法 JSON：" + json, ex);
        }
    }

    /** 用 refresh token 换一组新令牌，返回响应 JSON 原文。 */
    public static String refreshTokens(MockMvc mockMvc, String refreshToken) throws Exception {
        return mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", CLIENT_ID)
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
    }

    private static String queryParam(String url, String name) {
        String query = URI.create(url).getQuery();
        assertThat(query).as("回调地址应带查询参数：%s", url).isNotNull();

        return Arrays.stream(query.split("&"))
                .map((pair) -> pair.split("=", 2))
                .filter((parts) -> parts.length == 2 && parts[0].equals(name))
                .map((parts) -> parts[1])
                .findFirst()
                .orElseThrow(() -> new AssertionError("回调地址中没有 " + name + " 参数：" + url));
    }
}
```

- [ ] **Step 2: 写失败的测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/config/JwtClaimsConfigTest.java`

```java
package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import com.aventador.unifiedlogin.support.OAuth2TestFlows;
import com.aventador.unifiedlogin.user.AppUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class JwtClaimsConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private JwtDecoder jwtDecoder;

    private static final String PASSWORD = "a valid password";

    @Test
    void accessTokenSubjectIsUserIdNotEmail() throws Exception {
        String email = "claims-sub@example.com";
        AppUser user = registrationService.register(email, PASSWORD);

        Jwt jwt = decodeAccessToken(email);

        assertThat(jwt.getSubject()).isEqualTo(user.getId().toString());
        assertThat(jwt.getSubject()).isNotEqualTo(email);
    }

    @Test
    void accessTokenCarriesEmailClaim() throws Exception {
        String email = "claims-email@example.com";
        registrationService.register(email, PASSWORD);

        Jwt jwt = decodeAccessToken(email);

        assertThat(jwt.getClaimAsString("email")).isEqualTo(email);
    }

    @Test
    void accessTokenCarriesNoRoleOrAuthorityClaim() throws Exception {
        String email = "claims-noroles@example.com";
        registrationService.register(email, PASSWORD);

        Jwt jwt = decodeAccessToken(email);

        // 规格书要求：认证中心不下发任何角色或权限信息
        assertThat(jwt.getClaims()).doesNotContainKeys("roles", "authorities", "scope_roles");
    }

    @Test
    void refreshedAccessTokenKeepsUserIdSubjectAndEmail() throws Exception {
        // 刷新令牌重新签发 access token 时同样走 customizer——这条分支若失守，
        // 用户在续期后会拿到 sub 为邮箱的令牌，产品侧的外键关联当场断裂
        String email = "claims-refresh@example.com";
        AppUser user = registrationService.register(email, PASSWORD);

        String first = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                        OAuth2TestFlows.login(mockMvc, email, PASSWORD)));
        String refreshed = OAuth2TestFlows.refreshTokens(mockMvc,
                OAuth2TestFlows.jsonField(first, "refresh_token"));

        Jwt jwt = jwtDecoder.decode(OAuth2TestFlows.jsonField(refreshed, "access_token"));

        assertThat(jwt.getSubject()).isEqualTo(user.getId().toString());
        assertThat(jwt.getClaimAsString("email")).isEqualTo(email);
    }

    @Test
    void idTokenSubjectMatchesAccessTokenSubject() throws Exception {
        String email = "claims-idtoken@example.com";
        AppUser user = registrationService.register(email, PASSWORD);

        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                        OAuth2TestFlows.login(mockMvc, email, PASSWORD)));

        Jwt idToken = jwtDecoder.decode(OAuth2TestFlows.jsonField(tokenResponse, "id_token"));

        assertThat(idToken.getSubject()).isEqualTo(user.getId().toString());
    }

    private Jwt decodeAccessToken(String email) throws Exception {
        // 必须真实登录：.with(user(...)) 造的主体没有 FactorGrantedAuthority，
        // 框架推导不出认证时间会直接抛异常
        String tokenResponse = OAuth2TestFlows.exchangeCode(mockMvc,
                OAuth2TestFlows.authorizeAndExtractCode(mockMvc,
                        OAuth2TestFlows.login(mockMvc, email, PASSWORD)));

        return jwtDecoder.decode(OAuth2TestFlows.jsonField(tokenResponse, "access_token"));
    }
}
```

- [ ] **Step 3: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=JwtClaimsConfigTest`
Expected: FAIL — `accessTokenSubjectIsUserIdNotEmail` 与 `idTokenSubjectMatchesAccessTokenSubject` 失败（实际 `sub` 为邮箱），`accessTokenCarriesEmailClaim` 失败（不存在 `email` claim）。`accessTokenCarriesNoRoleOrAuthorityClaim` 此时应已通过——它断言的是「不该有的东西没有」

- [ ] **Step 4: 写 JWT 定制配置**

`auth-server/src/main/java/com/aventador/unifiedlogin/config/JwtClaimsConfig.java`

`principal.getName()` 在此处即登录时使用的邮箱（由 `AppUserDetailsService` 决定）。刷新令牌重新签发 access token 时同样会走这里，因此不需要额外处理：

```java
package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.EmailAddress;
import com.aventador.unifiedlogin.user.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class JwtClaimsConfig {

    private final UserService userService;

    public JwtClaimsConfig(UserService userService) {
        this.userService = userService;
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            String tokenType = context.getTokenType().getValue();
            boolean isAccessToken = OAuth2TokenType.ACCESS_TOKEN.getValue().equals(tokenType);
            boolean isIdToken = OidcParameterNames.ID_TOKEN.equals(tokenType);
            if (!isAccessToken && !isIdToken) {
                return;
            }

            // 注意：刷新令牌授权时 principal 是首次登录时序列化进 oauth2_authorization 表的
            // 快照，最长可在 refresh token 的 30 天寿命内被反复复用。因此这里的查找 key 是
            // 「登录时刻的邮箱」而非当前邮箱——将来实现「修改邮箱」功能时必须同步处理这里
            // （改完邮箱后旧 refresh token 会查不到人），否则表现为改邮箱即被强制登出。
            AppUser user = userService.findByEmail(new EmailAddress(context.getPrincipal().getName()))
                    .orElseThrow(() -> new IllegalStateException("签发令牌时找不到对应用户"));

            context.getClaims().subject(user.getId().toString());
            context.getClaims().claim("email", user.getEmail());
        };
    }
}
```

- [ ] **Step 5: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=JwtClaimsConfigTest`
Expected: PASS，5 个测试全部通过

- [ ] **Step 6: 运行全部测试**

Run: `cd auth-server && ./mvnw test`
Expected: 全部通过

- [ ] **Step 7: 提交**

```bash
git add auth-server/src
git commit -m "feat(config): 令牌主体改为用户 ID 并附带邮箱

各产品需要一个永不变更的标识来关联本地数据，邮箱可被修改因而
不适合承担该职责，故把 sub 定为用户 UUID，邮箱另以独立字段下发。"
```

---

### Task 10: 授权码 + PKCE 完整流程与回调白名单

**Files:**
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/config/AuthorizationCodeFlowTest.java`

**Interfaces:**
- Consumes: 前九个 Task 的全部产出
- Produces: 无新增生产代码。本任务是协议一致性的验收关卡——若测试不通过，说明前面某个环节配置有误，需回头修正而非放宽断言

- [ ] **Step 1: 写完整流程测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/config/AuthorizationCodeFlowTest.java`

复用 Task 9 建立的 `OAuth2TestFlows`。预期失败的请求需要自行构造，因为辅助类的 `exchangeCode` 断言的是成功路径：

```java
package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.aventador.unifiedlogin.support.OAuth2TestFlows;

import java.util.Map;

import static com.aventador.unifiedlogin.support.OAuth2TestFlows.CLIENT_ID;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.CODE_VERIFIER;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.REDIRECT_URI;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.authorizeAndExtractCode;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.authorizeUri;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.validAuthorizeParams;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.exchangeCode;
import static com.aventador.unifiedlogin.support.OAuth2TestFlows.jsonField;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class AuthorizationCodeFlowTest {

    private static final String USER_EMAIL = "flow@example.com";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    private static final String PASSWORD = "a valid password";

    private MockHttpSession session;

    @BeforeEach
    void createUserAndLogin() throws Exception {
        if (!registrationService.isEmailTaken(USER_EMAIL)) {
            registrationService.register(USER_EMAIL, PASSWORD);
        }
        // 走真实登录：.with(user(...)) 的主体缺少 FactorGrantedAuthority，
        // 框架签发 token 时推导不出认证时间会直接抛异常
        session = OAuth2TestFlows.login(mockMvc, USER_EMAIL, PASSWORD);
    }

    @Test
    void authenticatedUserExchangesCodeForTokens() throws Exception {
        String code = authorizeAndExtractCode(mockMvc, session);

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.refresh_token").exists())
                .andExpect(jsonPath("$.id_token").exists())
                .andExpect(jsonPath("$.token_type").value("Bearer"));
    }

    @Test
    void tokenRequestWithWrongVerifierIsRejected() throws Exception {
        String code = authorizeAndExtractCode(mockMvc, session);

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", "wrong-verifier-value-that-does-not-match-challenge"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void authorizationCodeCannotBeUsedTwice() throws Exception {
        String code = authorizeAndExtractCode(mockMvc, session);

        exchangeCode(mockMvc, code);

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", CLIENT_ID)
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isBadRequest());
    }

    @Test
    void authorizationRequestWithoutPkceIsRejected() throws Exception {
        Map<String, String> params = validAuthorizeParams();
        params.remove("code_challenge");
        params.remove("code_challenge_method");

        mockMvc.perform(get(authorizeUri(params)).session(session))
                .andExpect(status().isBadRequest());
    }

    @Test
    void redirectUriOutsideWhitelistIsRejectedWithoutRedirecting() throws Exception {
        Map<String, String> params = validAuthorizeParams();
        params.put("redirect_uri", "https://attacker.example.com/steal");

        MvcResult result = mockMvc.perform(get(authorizeUri(params)).session(session))
                .andExpect(status().isBadRequest())
                .andReturn();

        // 关键断言：绝不能发生指向攻击者地址的重定向
        assertThat(result.getResponse().getRedirectedUrl()).isNull();
    }

    @Test
    void userinfoReturnsSubjectWithValidAccessToken() throws Exception {
        // Task 8 只验证了「无 token 得 401」；这里补上正向链路：带合法 token 得 200
        String tokenResponse = exchangeCode(mockMvc, authorizeAndExtractCode(mockMvc, session));
        String accessToken = jsonField(tokenResponse, "access_token");

        mockMvc.perform(get("/userinfo").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").exists());
    }

    @Test
    void refreshTokenRotatesAndOldOneIsRejected() throws Exception {
        String tokenResponse = exchangeCode(mockMvc, authorizeAndExtractCode(mockMvc, session));
        String firstRefreshToken = jsonField(tokenResponse, "refresh_token");

        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", CLIENT_ID)
                        .param("refresh_token", firstRefreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refresh_token").exists());

        // 轮转后旧 refresh token 必须失效
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", CLIENT_ID)
                        .param("refresh_token", firstRefreshToken))
                .andExpect(status().isBadRequest());
    }
}
```

- [ ] **Step 2: 运行测试**

Run: `cd auth-server && ./mvnw test -Dtest=AuthorizationCodeFlowTest`
Expected: 7 个测试全部 PASS。

若出现失败，按以下对照排查，**不要放宽断言**：
- `authorizationRequestWithoutPkceIsRejected` 失败 → Task 7 的 `requireProofKey(true)` 未生效
- `refreshTokenRotatesAndOldOneIsRejected` 最后一步返回 200 → Task 7 的 `reuseRefreshTokens(false)` 未生效
- `redirectUriOutsideWhitelistIsRejectedWithoutRedirecting` 发生了重定向 → 回调白名单配置有误，属于开放重定向漏洞，必须修复
- 所有测试报 404 → Task 8 的授权服务器过滤链未生效

- [ ] **Step 3: 运行全部测试**

Run: `cd auth-server && ./mvnw test`
Expected: 全部通过

- [ ] **Step 4: 提交**

```bash
git add auth-server/src/test
git commit -m "test(config): 补充授权码流程的协议一致性验收

覆盖换取令牌、校验码不符被拒、授权码不可重复使用、缺少 PKCE 被拒、
回调地址越权不发生跳转、刷新令牌轮转后旧令牌失效六种情况。"
```

---

### Task 11: 登录失败限流

**Files:**
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/security/LoginRateLimitProperties.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/security/LoginAttemptService.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/security/LoginAttemptEventListener.java`
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/security/LoginRateLimitFilter.java`
- Modify: `auth-server/src/main/java/com/aventador/unifiedlogin/config/SecurityConfig.java`
- Modify: `auth-server/src/main/resources/templates/login.html`
- Modify: `auth-server/src/main/resources/application.yml`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/security/LoginAttemptServiceTest.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/security/LoginRateLimitIntegrationTest.java`

**Interfaces:**
- Consumes: `EmailAddress.normalize`（Task 2）、`SecurityConfig`（Task 6）、登录表单流程
- Produces: `LoginAttemptService`，方法 `recordFailure(String email)`、`isLocked(String email): boolean`、`clearFailures(String email)`、`registerAttemptAndCheckRateLimit(String ip): boolean`（返回 true 表示已超限）

**两条关键设计约束**：

1. **对不存在与格式非法的邮箱同样计数并锁定**。若只对真实账号锁定，攻击者用「这个邮箱会不会被锁」就能反推账号是否存在，等于绕开了 Task 6 建立的防枚举。因此这里用 `EmailAddress.normalize` 而非 `new EmailAddress(...)`——后者遇到非法格式会抛异常。
2. **计数状态在应用内存中**，仅适用于单实例部署。多实例需改共享存储，此约束已写入规格书与本计划的已知限制。

- [ ] **Step 1: 添加 Caffeine 依赖**

在 `auth-server/pom.xml` 的依赖列表中追加。版本由 Spring Boot 管理（3.2.4），不要写死。注意 **groupId 带连字符、Java 包名不带**，这是该库的经典坑：

```xml
        <!-- 登录失败限流用的带过期计数 -->
        <dependency>
            <groupId>com.github.ben-manes.caffeine</groupId>
            <artifactId>caffeine</artifactId>
        </dependency>
```

- [ ] **Step 2: 写失败的服务单元测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/security/LoginAttemptServiceTest.java`

用可推进的假时钟测过期，不使用真实等待：

```java
package com.aventador.unifiedlogin.security;

import com.github.benmanes.caffeine.cache.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class LoginAttemptServiceTest {

    private MutableTicker ticker;
    private LoginAttemptService service;

    @BeforeEach
    void setUp() {
        ticker = new MutableTicker();
        service = new LoginAttemptService(new LoginRateLimitProperties(5, Duration.ofMinutes(15), 20), ticker);
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
    void countsFailuresIgnoringEmailCase() {
        service.recordFailure("User@Example.com");
        service.recordFailure("user@example.COM");
        service.recordFailure("  USER@EXAMPLE.COM  ");
        service.recordFailure("user@example.com");
        service.recordFailure("uSeR@eXaMpLe.CoM");

        assertThat(service.isLocked("user@example.com")).isTrue();
    }

    @Test
    void locksMalformedEmailToo() {
        // 防枚举：对格式非法的输入也要计数，否则「会不会被锁」泄漏账号是否存在
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

        ticker.advance(Duration.ofMinutes(15).plusSeconds(1));

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

    /** 可手动推进的时钟，避免测试真实等待 15 分钟。 */
    private static final class MutableTicker implements Ticker {

        private long nanos;

        @Override
        public long read() {
            return nanos;
        }

        void advance(Duration duration) {
            nanos += duration.toNanos();
        }
    }
}
```

- [ ] **Step 3: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=LoginAttemptServiceTest`
Expected: FAIL — 编译错误，`LoginAttemptService` 与 `LoginRateLimitProperties` 尚不存在

- [ ] **Step 4: 写配置项与限流服务**

`auth-server/src/main/java/com/aventador/unifiedlogin/security/LoginRateLimitProperties.java`

```java
package com.aventador.unifiedlogin.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "unified-login.login-rate-limit")
public record LoginRateLimitProperties(int maxFailuresPerEmail,
                                       Duration emailLockDuration,
                                       int maxAttemptsPerIpPerMinute) {
}
```

`auth-server/src/main/java/com/aventador/unifiedlogin/security/LoginAttemptService.java`

注意 Caffeine 的 groupId 带连字符（`com.github.ben-manes.caffeine`）而包名不带（`com.github.benmanes.caffeine`）：

```java
package com.aventador.unifiedlogin.security;

import com.aventador.unifiedlogin.user.EmailAddress;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class LoginAttemptService {

    private static final Duration IP_WINDOW = Duration.ofMinutes(1);
    private static final int MAX_TRACKED_KEYS = 10_000;

    private final LoginRateLimitProperties properties;
    private final Cache<String, Integer> failuresByEmail;
    private final Cache<String, Integer> attemptsByIp;

    public LoginAttemptService(LoginRateLimitProperties properties, Ticker ticker) {
        this.properties = properties;
        this.failuresByEmail = Caffeine.newBuilder()
                .expireAfterWrite(properties.emailLockDuration())
                .maximumSize(MAX_TRACKED_KEYS)
                .ticker(ticker)
                .build();
        this.attemptsByIp = Caffeine.newBuilder()
                .expireAfterWrite(IP_WINDOW)
                .maximumSize(MAX_TRACKED_KEYS)
                .ticker(ticker)
                .build();
    }

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

    /** 供测试在用例之间隔离状态；生产代码不调用。 */
    void clearAll() {
        failuresByEmail.invalidateAll();
        attemptsByIp.invalidateAll();
    }
}
```

- [ ] **Step 5: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=LoginAttemptServiceTest`
Expected: PASS，10 个测试全部通过

- [ ] **Step 6: 写失败的集成测试**

`auth-server/src/test/java/com/aventador/unifiedlogin/security/LoginRateLimitIntegrationTest.java`

```java
package com.aventador.unifiedlogin.security;

import com.aventador.unifiedlogin.PostgresTestConfig;
import com.aventador.unifiedlogin.registration.RegistrationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfig.class)
class LoginRateLimitIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @BeforeEach
    void resetCounters() {
        // Spring 会在测试类之间复用同一个应用上下文，限流计数是单例状态，
        // 不清零会让用例互相干扰
        loginAttemptService.clearAll();
    }

    @Test
    void locksAccountAfterFiveFailuresEvenWithCorrectPassword() throws Exception {
        String email = "lockout@example.com";
        registrationService.register(email, "a valid password");

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(formLogin("/login").user(email).password("wrong password"))
                    .andExpect(unauthenticated());
        }

        // 第 6 次即使密码正确也必须被拒
        mockMvc.perform(formLogin("/login").user(email).password("a valid password"))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?locked"));
    }

    @Test
    void locksUnknownEmailToo() throws Exception {
        String email = "ghost-lockout@example.com";

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(formLogin("/login").user(email).password("any password"))
                    .andExpect(unauthenticated());
        }

        mockMvc.perform(formLogin("/login").user(email).password("any password"))
                .andExpect(redirectedUrl("/login?locked"));
    }

    @Test
    void successfulLoginResetsFailureCount() throws Exception {
        String email = "reset-count@example.com";
        registrationService.register(email, "a valid password");

        for (int i = 0; i < 4; i++) {
            mockMvc.perform(formLogin("/login").user(email).password("wrong password"))
                    .andExpect(unauthenticated());
        }

        mockMvc.perform(formLogin("/login").user(email).password("a valid password"))
                .andExpect(authenticated());

        // 计数已清零，再错 4 次仍不该锁
        for (int i = 0; i < 4; i++) {
            mockMvc.perform(formLogin("/login").user(email).password("wrong password"))
                    .andExpect(unauthenticated());
        }

        mockMvc.perform(formLogin("/login").user(email).password("a valid password"))
                .andExpect(authenticated());
    }

    @Test
    void rejectsWithTooManyRequestsBeyondIpLimit() throws Exception {
        // 用不同邮箱避免先触发账号锁定，从而单独验证 IP 维度
        for (int i = 0; i < 20; i++) {
            mockMvc.perform(formLogin("/login").user("ip-" + i + "@example.com").password("any password"));
        }

        mockMvc.perform(formLogin("/login").user("ip-last@example.com").password("any password"))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void loginPageShowsLockedNotice() throws Exception {
        String email = "notice@example.com";
        registrationService.register(email, "a valid password");

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(formLogin("/login").user(email).password("wrong password"));
        }

        mockMvc.perform(formLogin("/login").user(email).password("a valid password"))
                .andExpect(redirectedUrl("/login?locked"));
    }
}
```

- [ ] **Step 7: 运行测试确认失败**

Run: `cd auth-server && ./mvnw test -Dtest=LoginRateLimitIntegrationTest`
Expected: FAIL — 限流尚未接入过滤链，连续失败后第 6 次仍按正常登录处理

- [ ] **Step 8: 写事件监听器与限流过滤器**

`auth-server/src/main/java/com/aventador/unifiedlogin/security/LoginAttemptEventListener.java`

```java
package com.aventador.unifiedlogin.security;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class LoginAttemptEventListener {

    private final LoginAttemptService loginAttemptService;

    public LoginAttemptEventListener(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    /**
     * 账号不存在时 DaoAuthenticationProvider 会把 UsernameNotFoundException 转成
     * BadCredentialsException（默认 hideUserNotFoundExceptions=true），因此这里
     * 天然对不存在的邮箱也会计数，正是防枚举所需要的。
     */
    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {
        loginAttemptService.recordFailure(event.getAuthentication().getName());
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        loginAttemptService.clearFailures(event.getAuthentication().getName());
    }
}
```

`auth-server/src/main/java/com/aventador/unifiedlogin/security/LoginRateLimitFilter.java`

```java
package com.aventador.unifiedlogin.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class LoginRateLimitFilter extends OncePerRequestFilter {

    private static final String LOGIN_PATH = "/login";
    private static final String USERNAME_PARAMETER = "username";

    private final LoginAttemptService loginAttemptService;

    public LoginRateLimitFilter(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!isLoginSubmission(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (loginAttemptService.registerAttemptAndCheckRateLimit(request.getRemoteAddr())) {
            response.sendError(HttpStatus.TOO_MANY_REQUESTS.value(), "登录尝试过于频繁，请稍后再试");
            return;
        }

        if (loginAttemptService.isLocked(request.getParameter(USERNAME_PARAMETER))) {
            response.sendRedirect(request.getContextPath() + "/login?locked");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private static boolean isLoginSubmission(HttpServletRequest request) {
        return "POST".equalsIgnoreCase(request.getMethod()) && LOGIN_PATH.equals(request.getServletPath());
    }
}
```

- [ ] **Step 9: 接入过滤链并启用配置**

`auth-server/src/main/java/com/aventador/unifiedlogin/config/SecurityConfig.java` 整体替换为：

```java
package com.aventador.unifiedlogin.config;

import com.aventador.unifiedlogin.security.LoginAttemptService;
import com.aventador.unifiedlogin.security.LoginRateLimitFilter;
import com.aventador.unifiedlogin.security.LoginRateLimitProperties;
import com.github.benmanes.caffeine.cache.Ticker;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(LoginRateLimitProperties.class)
public class SecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          LoginAttemptService loginAttemptService) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        // /error 必须放行：Spring Security 7 默认拦截 ERROR dispatch，
                        // 不放行时未捕获异常的错误页转发会被再拦一次，500 都呈现不出来
                        .requestMatchers("/register", "/login", "/error").permitAll()
                        .anyRequest().authenticated())
                .formLogin((formLogin) -> formLogin
                        // 必须指定自定义登录页：默认配置会启用登录页生成过滤器，遮蔽 Thymeleaf 模板
                        .loginPage("/login"))
                .addFilterBefore(new LoginRateLimitFilter(loginAttemptService),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /** 生产使用系统时钟；测试可覆盖为可推进的假时钟。 */
    @Bean
    public Ticker loginAttemptTicker() {
        return Ticker.systemTicker();
    }

    /** 显式声明，确保认证成功与失败事件一定被发布，限流的计数不依赖自动配置的默认行为。 */
    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher publisher) {
        return new DefaultAuthenticationEventPublisher(publisher);
    }
}
```

在 `auth-server/src/main/resources/application.yml` 的 `unified-login:` 节点下追加（与 `clients` 同级）：

```yaml
  login-rate-limit:
    max-failures-per-email: 5
    email-lock-duration: 15m
    max-attempts-per-ip-per-minute: 20
```

- [ ] **Step 10: 在登录页显示锁定提示**

在 `auth-server/src/main/resources/templates/login.html` 的错误提示下方追加一行：

```html
    <p th:if="${param.locked}" data-testid="login-locked">尝试次数过多，请在 15 分钟后再试</p>
```

- [ ] **Step 11: 运行测试确认通过**

Run: `cd auth-server && ./mvnw test -Dtest=LoginRateLimitIntegrationTest`
Expected: PASS，5 个测试全部通过

- [ ] **Step 12: 运行全部测试**

Run: `cd auth-server && ./mvnw test`
Expected: 全部通过。若其他登录相关测试类出现意外的 429 或 `/login?locked`，说明限流状态在测试类之间泄漏——应在受影响的测试类补 `loginAttemptService.clearAll()`，而不是调高阈值掩盖问题

- [ ] **Step 13: 提交**

```bash
git add auth-server/src
git commit -m "feat(security): 新增登录失败限流

同一邮箱连续失败五次后锁定十五分钟，同一地址每分钟最多尝试二十次。
对不存在与格式非法的邮箱同样计数，避免「会不会被锁」反过来泄漏
账号是否存在。计数保存在应用内存中，仅适用于单实例部署。"
```

---

### Task 12: demo-web-a 与端到端验收

**Files:**
- Create: `demo/demo-web-a/package.json`
- Create: `demo/demo-web-a/index.html`
- Create: `demo/demo-web-a/vite.config.ts`
- Create: `demo/demo-web-a/src/main.ts`
- Create: `demo/demo-web-a/src/auth.ts`
- Create: `e2e/package.json`
- Create: `e2e/playwright.config.ts`
- Create: `e2e/tests/register-and-login.spec.ts`
- Create: `docs/local-development.md`

**Interfaces:**
- Consumes: 认证中心全部端点、client `demo-web-a`
- Produces: 可运行的 demo 产品与可重复执行的端到端用例

**前置说明**：本任务的 `auth.ts` 是一次性的最小实现，仅为验证阶段一链路。阶段二会用正式的 Web TS 套件替换它，届时删除此文件。

- [ ] **Step 1: 创建 demo-web-a 项目文件**

`demo/demo-web-a/package.json`

```json
{
  "name": "demo-web-a",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite --host 127.0.0.1 --port 5173 --strictPort",
    "build": "tsc -b && vite build",
    "preview": "vite preview --port 5173 --strictPort"
  },
  "devDependencies": {
    "typescript": "^5.7.0",
    "vite": "^7.0.0"
  }
}
```

`demo/demo-web-a/vite.config.ts`

```typescript
import { defineConfig } from 'vite'

export default defineConfig({
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
  },
})
```

`demo/demo-web-a/index.html`

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Demo Web A</title>
</head>
<body>
<main>
    <h1>Demo Web A</h1>
    <div id="app"></div>
</main>
<script type="module" src="/src/main.ts"></script>
</body>
</html>
```

- [ ] **Step 2: 写 PKCE 与授权码逻辑**

`demo/demo-web-a/src/auth.ts`

token 只保存在模块级变量中，不写入任何持久化存储：

```typescript
const ISSUER = 'http://localhost:9000'
const CLIENT_ID = 'demo-web-a'
const REDIRECT_URI = 'http://localhost:5173/callback'
const VERIFIER_KEY = 'demo-web-a.code_verifier'
const STATE_KEY = 'demo-web-a.state'

let accessToken: string | null = null
let idTokenEmail: string | null = null

function randomString(byteLength: number): string {
  const bytes = new Uint8Array(byteLength)
  crypto.getRandomValues(bytes)
  return base64UrlEncode(bytes)
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ''
  bytes.forEach((b) => {
    binary += String.fromCharCode(b)
  })
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function deriveChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64UrlEncode(new Uint8Array(digest))
}

export async function startLogin(): Promise<void> {
  const verifier = randomString(32)
  const state = randomString(16)
  sessionStorage.setItem(VERIFIER_KEY, verifier)
  sessionStorage.setItem(STATE_KEY, state)

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid',
    state,
    code_challenge: await deriveChallenge(verifier),
    code_challenge_method: 'S256',
  })

  window.location.assign(`${ISSUER}/oauth2/authorize?${params.toString()}`)
}

export async function completeLogin(search: string): Promise<void> {
  const params = new URLSearchParams(search)
  const code = params.get('code')
  const returnedState = params.get('state')
  const expectedState = sessionStorage.getItem(STATE_KEY)
  const verifier = sessionStorage.getItem(VERIFIER_KEY)

  if (!code || !verifier) {
    throw new Error('回调缺少必要参数')
  }
  if (!returnedState || returnedState !== expectedState) {
    throw new Error('state 校验失败，拒绝换取令牌')
  }

  sessionStorage.removeItem(STATE_KEY)
  sessionStorage.removeItem(VERIFIER_KEY)

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
  })

  const response = await fetch(`${ISSUER}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })

  if (!response.ok) {
    throw new Error(`换取令牌失败：${response.status}`)
  }

  const payload = await response.json()
  accessToken = payload.access_token
  idTokenEmail = readEmailFromIdToken(payload.id_token)
}

function readEmailFromIdToken(idToken: string): string {
  const claims = JSON.parse(atob(idToken.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')))
  // sub 是永不变更的用户 UUID，email 是可变的显示用字段，此处要显示的是后者
  return claims.email
}

export function isLoggedIn(): boolean {
  return accessToken !== null
}

export function currentUser(): string | null {
  return idTokenEmail
}
```

- [ ] **Step 3: 写页面入口**

`demo/demo-web-a/src/main.ts`

```typescript
import { completeLogin, currentUser, isLoggedIn, startLogin } from './auth'

const app = document.querySelector<HTMLDivElement>('#app')!

async function render(): Promise<void> {
  if (window.location.pathname === '/callback') {
    try {
      await completeLogin(window.location.search)
      window.history.replaceState({}, '', '/')
    }
    catch (error) {
      app.innerHTML = `<p data-testid="auth-error">${(error as Error).message}</p>`
      return
    }
  }

  if (isLoggedIn()) {
    app.innerHTML = `<p data-testid="signed-in-user">已登录：${currentUser()}</p>`
    return
  }

  app.innerHTML = '<button type="button" data-testid="login-button">登录</button>'
  document.querySelector('[data-testid="login-button"]')!
    .addEventListener('click', () => { void startLogin() })
}

void render()
```

- [ ] **Step 4: 写 Playwright 配置与用例**

`e2e/package.json`

```json
{
  "name": "unified-login-e2e",
  "private": true,
  "type": "module",
  "scripts": {
    "test": "playwright test"
  },
  "devDependencies": {
    "@playwright/test": "^1.50.0"
  }
}
```

`e2e/playwright.config.ts`

按静默运行要求，固定为无头模式：

```typescript
import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  use: {
    // 复用本机已安装的 Google Chrome，不下载独立 Chromium
    channel: 'chrome',
    headless: true,
    baseURL: 'http://localhost:5173',
  },
})
```

`e2e/tests/register-and-login.spec.ts`

```typescript
import { expect, test } from '@playwright/test'

const AUTH_BASE = 'http://localhost:9000'

function uniqueEmail(): string {
  return `e2e-${Date.now()}-${Math.floor(Math.random() * 10000)}@example.com`
}

test('新用户注册后可通过统一登录进入 demo-web-a', async ({ page }) => {
  const email = uniqueEmail()
  const password = 'a valid password'

  await page.goto(`${AUTH_BASE}/register`)
  await page.fill('#email', email)
  await page.fill('#password', password)
  await page.click('button[type="submit"]')

  await expect(page.getByTestId('login-registered')).toBeVisible()

  await page.goto('/')
  await page.getByTestId('login-button').click()

  await page.waitForURL(/\/login/)
  await page.fill('#username', email)
  await page.fill('#password', password)
  await page.click('button[type="submit"]')

  await page.waitForURL('http://localhost:5173/**')
  await expect(page.getByTestId('signed-in-user')).toBeVisible()
})

test('已在认证中心登录后再次进入产品无需重新输入密码', async ({ page }) => {
  const email = uniqueEmail()
  const password = 'a valid password'

  await page.goto(`${AUTH_BASE}/register`)
  await page.fill('#email', email)
  await page.fill('#password', password)
  await page.click('button[type="submit"]')

  await page.fill('#username', email)
  await page.fill('#password', password)
  await page.click('button[type="submit"]')

  await page.goto('/')
  await page.getByTestId('login-button').click()

  // 认证中心已有会话，应直接回跳而不出现登录表单
  await expect(page.getByTestId('signed-in-user')).toBeVisible()
  await expect(page.locator('#username')).toHaveCount(0)
})

test('密码错误时提示信息不透露账号是否存在', async ({ page }) => {
  const email = uniqueEmail()

  await page.goto(`${AUTH_BASE}/register`)
  await page.fill('#email', email)
  await page.fill('#password', 'a valid password')
  await page.click('button[type="submit"]')

  await page.fill('#username', email)
  await page.fill('#password', 'wrong password')
  await page.click('button[type="submit"]')
  const wrongPasswordMessage = await page.getByTestId('login-error').textContent()

  await page.goto(`${AUTH_BASE}/login`)
  await page.fill('#username', uniqueEmail())
  await page.fill('#password', 'a valid password')
  await page.click('button[type="submit"]')
  const unknownAccountMessage = await page.getByTestId('login-error').textContent()

  expect(wrongPasswordMessage).toBe(unknownAccountMessage)
})
```

- [ ] **Step 5: 写本地启动说明**

`docs/local-development.md`

```markdown
# 本地开发与验收

## 前置

- Java 17、Maven、Node 22+、pnpm、Docker（供 Testcontainers 使用）
- 本地 PostgreSQL：`docker run --rm -e POSTGRES_DB=unified_login -e POSTGRES_USER=unified_login -e POSTGRES_PASSWORD=unified_login -p 5432:5432 postgres:16-alpine`

## 启动

1. 认证中心：`cd auth-server && ./mvnw spring-boot:run`（监听 9000）
2. demo-web-a：`cd demo/demo-web-a && pnpm install && pnpm dev`（监听 5173）

## 端到端验收

```bash
cd e2e && pnpm install && pnpm test
```

配置已用 `channel: "chrome"` 复用本机 Google Chrome，**不要执行 `playwright install`**。

E2E 的全部用例都从同一个地址发起登录，反复重跑容易撞上每分钟 20 次的地址限流。
跑 E2E 时用环境变量把该阈值调高即可：

```bash
UNIFIED_LOGIN_LOGIN_RATE_LIMIT_MAXATTEMPTSPERIPPERMINUTE=1000 ./mvnw spring-boot:run
```

这是**配置值差异，不是代码分支**——限流的判定逻辑与生产完全是同一条路径，只是阈值不同。
账号维度的锁定阈值不要调整，E2E 用例本身不会触发它。

## 手工验证限流

限流的自动化覆盖在 `LoginRateLimitIntegrationTest`（真实 Spring 上下文 + 真实数据库）。
不放进 E2E 是因为一旦触发锁定会干扰同批次的其他用例。若要手工确认，用同一个邮箱连续
输错 5 次密码，第 6 次即使密码正确也会跳到 `/login?locked` 并显示锁定提示。

## 收尾

验收结束后停掉 PostgreSQL 容器与两个开发服务，避免端口与资源占用。
```

- [ ] **Step 6: 运行端到端验收**

依次启动 PostgreSQL、认证中心、demo-web-a，然后：

Run: `cd e2e && pnpm install && pnpm test`（配置已指定 `channel: 'chrome'` 复用本机 Chrome，不执行任何 `playwright install`）
Expected: 3 个用例全部 PASS

- [ ] **Step 7: 停止本地服务**

按本地服务管理要求，验收通过后停掉 PostgreSQL 容器、认证中心与 demo-web-a 的开发服务，确认端口 5432、9000、5173 均已释放。

- [ ] **Step 8: 提交**

```bash
git add demo e2e docs/local-development.md
git commit -m "feat(demo): 新增 demo-web-a 与端到端验收用例

以最小前端验证注册、登录、授权码换取令牌的完整链路，并覆盖
已有会话时的免登与登录失败提示不泄漏账号存在性两种情况。"
```

---

## 阶段一完成标准

全部满足才算通过：

1. `cd auth-server && ./mvnw test` 全绿。
2. `cd e2e && pnpm test` 三个用例全绿。
3. 人工在浏览器完成一次注册与登录，确认能进入 demo-web-a 的已登录界面。
4. 认证中心重启后，此前签发的令牌仍可验签（验证签名密钥确实落盘复用）。
5. 数据库中 `app_user` 表内密码列为 `$argon2id$` 开头的哈希，不存在任何明文密码。
6. 解开一个实际签发的 access token，确认 `sub` 是 UUID 而非邮箱，且载荷中不含任何角色或权限字段。
7. 手工用同一邮箱连续输错 5 次密码，确认第 6 次即使密码正确也被拒绝并跳转到 `/login?locked`。
