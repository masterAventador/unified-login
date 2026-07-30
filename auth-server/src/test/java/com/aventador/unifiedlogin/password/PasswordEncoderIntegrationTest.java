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
