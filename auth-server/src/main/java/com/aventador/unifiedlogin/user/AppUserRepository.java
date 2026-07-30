package com.aventador.unifiedlogin.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface AppUserRepository extends JpaRepository<AppUser, UUID> {

    Optional<AppUser> findByEmail(String email);

    boolean existsByEmail(String email);

    @Query("""
            SELECT user
            FROM AppUser user
            WHERE LOWER(user.email) LIKE LOWER(CONCAT('%', :email, '%')) ESCAPE '!'
              AND (:status IS NULL OR user.status = :status)
            """)
    Page<AppUser> search(
            @Param("email") String email,
            @Param("status") UserStatus status,
            Pageable pageable);
}
