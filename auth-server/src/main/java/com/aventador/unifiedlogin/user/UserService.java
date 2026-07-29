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
     */
    @Transactional
    public AppUser createUser(EmailAddress email, String passwordHash) {
        AppUser user = new AppUser(UUID.randomUUID(), email, passwordHash, Instant.now());
        return repository.save(user);
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
