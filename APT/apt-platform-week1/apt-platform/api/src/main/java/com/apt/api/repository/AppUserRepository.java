package com.apt.api.repository;

import com.apt.core.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser, UUID> {

    Optional<AppUser> findByUsername(String username);

    boolean existsByUsername(String username);

    /** Increment failed login counter — called on bad password */
    @Modifying
    @Transactional
    @Query("UPDATE AppUser u SET u.failedLoginAttempts = u.failedLoginAttempts + 1 WHERE u.username = :username")
    void incrementFailedLogins(String username);

    /** Lock account after too many failures */
    @Modifying
    @Transactional
    @Query("UPDATE AppUser u SET u.accountLocked = true WHERE u.username = :username")
    void lockAccount(String username);

    /** Reset failed count on successful login */
    @Modifying
    @Transactional
    @Query("UPDATE AppUser u SET u.failedLoginAttempts = 0, u.lastLogin = CURRENT_TIMESTAMP WHERE u.username = :username")
    void resetFailedLogins(String username);
}
