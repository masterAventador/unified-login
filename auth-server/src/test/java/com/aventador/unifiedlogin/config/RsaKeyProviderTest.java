package com.aventador.unifiedlogin.config;

import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

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
}
