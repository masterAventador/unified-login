package com.aventador.unifiedlogin.admin;

import com.aventador.unifiedlogin.password.WeakPasswordException;
import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/admin/users")
public class AdminUserController {

    private static final int MAX_PAGE_SIZE = 100;

    private final AdminUserService adminUserService;

    public AdminUserController(AdminUserService adminUserService) {
        this.adminUserService = adminUserService;
    }

    @GetMapping
    public UserPage list(
            @RequestParam(defaultValue = "") String email,
            @RequestParam(required = false) UserStatus status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        if (page < 0 || size < 1 || size > MAX_PAGE_SIZE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "分页参数无效");
        }
        return UserPage.from(adminUserService.list(email, status, page, size));
    }

    @PostMapping("/{id}/disable")
    public ResponseEntity<Void> disable(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID id) {
        adminUserService.disable(UUID.fromString(jwt.getSubject()), id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/enable")
    public ResponseEntity<Void> enable(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID id) {
        adminUserService.enable(UUID.fromString(jwt.getSubject()), id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/reset-password")
    public ResponseEntity<Void> resetPassword(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID id,
            @RequestBody PasswordResetRequest request) {
        adminUserService.resetPassword(
                UUID.fromString(jwt.getSubject()),
                id,
                request.newPassword());
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(WeakPasswordException.class)
    ResponseEntity<Void> weakPassword() {
        return ResponseEntity.badRequest().build();
    }

    public record PasswordResetRequest(String newPassword) {
    }

    public record UserPage(
            List<UserSummary> content,
            int page,
            int size,
            long totalElements,
            int totalPages) {

        static UserPage from(Page<AppUser> users) {
            return new UserPage(
                    users.getContent().stream().map(UserSummary::from).toList(),
                    users.getNumber(),
                    users.getSize(),
                    users.getTotalElements(),
                    users.getTotalPages());
        }
    }

    public record UserSummary(
            UUID id,
            String email,
            UserStatus status,
            boolean emailVerified,
            boolean platformAdmin,
            Instant passwordChangedAt,
            Instant createdAt,
            Instant updatedAt) {

        static UserSummary from(AppUser user) {
            return new UserSummary(
                    user.getId(),
                    user.getEmail(),
                    user.getStatus(),
                    user.isEmailVerified(),
                    user.isPlatformAdmin(),
                    user.getPasswordChangedAt(),
                    user.getCreatedAt(),
                    user.getUpdatedAt());
        }
    }
}
