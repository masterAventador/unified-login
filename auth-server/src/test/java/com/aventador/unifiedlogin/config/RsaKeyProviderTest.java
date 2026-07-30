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
