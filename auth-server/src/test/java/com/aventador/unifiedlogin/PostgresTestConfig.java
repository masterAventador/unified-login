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

    @Bean
    DynamicPropertyRegistrar jwtKeyStoreRegistrar() throws IOException {
        Path keyDir = Files.createTempDirectory("unified-login-test-keys");
        keyDir.toFile().deleteOnExit();
        return (registry) -> registry.add("unified-login.jwt-key-store",
                () -> keyDir.resolve("jwt-signing-key.json").toString());
    }
}
