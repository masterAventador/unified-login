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
