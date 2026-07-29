package com.aventador.unifiedlogin.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import org.springframework.data.domain.Persistable;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "app_user")
public class AppUser implements Persistable<UUID> {

    @Id
    private UUID id;

    /**
     * ID 由应用层生成而非数据库自增，Spring Data 无法用「id 是否为 null」判定新旧实体。
     * 不实现 Persistable 时 save() 会走 merge()，对每个新实体多打一次冗余 SELECT。
     */
    @Transient
    private boolean isNew = false;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserStatus status;

    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified;

    @Column(name = "is_platform_admin", nullable = false)
    private boolean platformAdmin;

    @Column(name = "password_changed_at", nullable = false)
    private Instant passwordChangedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected AppUser() {
        // JPA 要求的无参构造器
    }

    // 构造器收 EmailAddress 而非裸 String：「落库小写」由类型系统保证，不靠调用方自觉
    AppUser(UUID id, EmailAddress email, String passwordHash, Instant now) {
        this.id = id;
        this.email = email.value();
        this.passwordHash = passwordHash;
        this.status = UserStatus.ACTIVE;
        this.emailVerified = true;
        this.platformAdmin = false;
        this.passwordChangedAt = now;
        this.createdAt = now;
        this.updatedAt = now;
        this.isNew = true;
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }

    @PostPersist
    @PostLoad
    void markNotNew() {
        this.isNew = false;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public UserStatus getStatus() {
        return status;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public boolean isPlatformAdmin() {
        return platformAdmin;
    }

    public Instant getPasswordChangedAt() {
        return passwordChangedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
