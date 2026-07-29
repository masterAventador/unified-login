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
