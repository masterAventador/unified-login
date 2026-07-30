package com.aventador.unifiedlogin;

import com.aventador.unifiedlogin.support.MutableTicker;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.DynamicPropertyRegistrar;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@TestConfiguration(proxyBeanMethods = false)
public class PostgresTestConfig {

    /**
     * 顶掉生产的系统时钟。登录限流的锁定时长以分钟计，用真实时间验证过期要等十几分钟；
     * 换成可推进的假时钟后，被测的产品代码路径完全不变，只是时间来源可控。
     */
    @Bean
    @Primary
    MutableTicker testTicker() {
        return new MutableTicker();
    }

    @Bean
    @ServiceConnection
    PostgreSQLContainer postgresContainer() {
        return new PostgreSQLContainer("postgres:16-alpine");
    }

    @Bean
    DynamicPropertyRegistrar jwtKeyStoreRegistrar() throws IOException {
        Path keyDir = Files.createTempDirectory("unified-login-test-keys");
        keyDir.toFile().deleteOnExit();
        return (registry) -> registry.add("unified-login.jwt-key-store",
                () -> keyDir.resolve("jwt-signing-key.json").toString());
    }
}
