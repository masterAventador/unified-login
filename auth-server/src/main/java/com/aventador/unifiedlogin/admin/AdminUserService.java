package com.aventador.unifiedlogin.admin;

import com.aventador.unifiedlogin.account.TokenRevocationService;
import com.aventador.unifiedlogin.account.UserTokenLock;
import com.aventador.unifiedlogin.password.PasswordPolicy;
import com.aventador.unifiedlogin.user.AppUser;
import com.aventador.unifiedlogin.user.AppUserRepository;
import com.aventador.unifiedlogin.user.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class AdminUserService {

    private final AppUserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final TokenRevocationService tokenRevocationService;

    private final UserTokenLock userTokenLock;

    public AdminUserService(
            AppUserRepository userRepository,
            PasswordEncoder passwordEncoder,
            TokenRevocationService tokenRevocationService,
            UserTokenLock userTokenLock) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenRevocationService = tokenRevocationService;
        this.userTokenLock = userTokenLock;
    }

    @Transactional(readOnly = true)
    public Page<AppUser> list(String email, UserStatus status, int page, int size) {
        return userRepository.search(
                escapeLike(email == null ? "" : email.strip()),
                status,
                PageRequest.of(page, size,
                        Sort.by(Sort.Direction.DESC, "createdAt")
                                .and(Sort.by(Sort.Direction.ASC, "id"))));
    }

    @Transactional
    public void disable(UUID actorId, UUID targetId) {
        if (actorId.equals(targetId)) {
            throw new SelfDisableException();
        }

        LockedUsers users = lockActorAndTarget(actorId, targetId);
        requireActiveAdministrator(users.actor());
        users.target().disable(Instant.now());
        tokenRevocationService.revokeAllTokensOf(targetId);
    }

    @Transactional
    public void enable(UUID actorId, UUID targetId) {
        LockedUsers users = lockActorAndTarget(actorId, targetId);
        requireActiveAdministrator(users.actor());
        users.target().enable(Instant.now());
    }

    @Transactional
    public void resetPassword(UUID actorId, UUID targetId, String newPassword) {
        PasswordPolicy.validate(newPassword);

        LockedUsers users = lockActorAndTarget(actorId, targetId);
        requireActiveAdministrator(users.actor());
        Instant changedAt = Instant.now();
        users.target().changePassword(passwordEncoder.encode(newPassword), changedAt);
        tokenRevocationService.revokeAllTokensOf(targetId);
    }

    private AppUser lockAndFind(UUID targetId) {
        if (userTokenLock.lockByUserId(targetId).isEmpty()) {
            throw new AdminUserNotFoundException();
        }
        return userRepository.findById(targetId)
                .orElseThrow(AdminUserNotFoundException::new);
    }

    private LockedUsers lockActorAndTarget(UUID actorId, UUID targetId) {
        if (actorId.equals(targetId)) {
            AppUser user = lockAndFind(actorId);
            return new LockedUsers(user, user);
        }

        UUID firstId = actorId.compareTo(targetId) < 0 ? actorId : targetId;
        UUID secondId = firstId.equals(actorId) ? targetId : actorId;
        AppUser first = lockAndFind(firstId);
        AppUser second = lockAndFind(secondId);
        return firstId.equals(actorId)
                ? new LockedUsers(first, second)
                : new LockedUsers(second, first);
    }

    private void requireActiveAdministrator(AppUser actor) {
        if (!actor.isPlatformAdmin() || actor.getStatus() != UserStatus.ACTIVE) {
            throw new AccessDeniedException("管理员账号不可用");
        }
    }

    private String escapeLike(String value) {
        return value
                .replace("!", "!!")
                .replace("%", "!%")
                .replace("_", "!_");
    }

    private record LockedUsers(AppUser actor, AppUser target) {
    }
}
