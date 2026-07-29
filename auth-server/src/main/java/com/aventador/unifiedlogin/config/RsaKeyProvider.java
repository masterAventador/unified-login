package com.aventador.unifiedlogin.config;

import com.nimbusds.jose.jwk.RSAKey;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.UUID;

public final class RsaKeyProvider {

    private static final int KEY_SIZE = 2048;

    private RsaKeyProvider() {
    }

    public static RSAKey loadOrCreate(Path keyFile) {
        try {
            if (Files.exists(keyFile)) {
                return RSAKey.parse(Files.readString(keyFile, StandardCharsets.UTF_8));
            }

            RSAKey generated = generate();
            Path parent = keyFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(keyFile, generated.toJSONString(), StandardCharsets.UTF_8);
            return generated;
        }
        catch (IOException ex) {
            throw new UncheckedIOException("无法读写 JWT 签名密钥文件：" + keyFile, ex);
        }
        catch (ParseException ex) {
            throw new IllegalStateException("JWT 签名密钥文件内容无法解析：" + keyFile, ex);
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
