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
