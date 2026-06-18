package com.apt.core.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * AppUser — a SOC platform operator, not a monitored entity.
 *
 * Roles determine what API endpoints and dashboard features are visible:
 *   ADMIN       — full access, user management, system config
 *   SOC_ANALYST — view + triage alerts, trigger manual responses
 *   VIEWER      — read-only dashboard access (management, auditors)
 *
 * We store a TOTP secret so analysts can set up Google Authenticator
 * for MFA (implemented in Week 3).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users", indexes = {
    @Index(name = "idx_users_username", columnList = "username", unique = true)
})
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;          // BCrypt hashed — never store plaintext

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole role;

    @Column(name = "totp_secret")
    private String totpSecret;            // Base32 seed for TOTP MFA (Week 3)

    @Column(name = "mfa_enabled")
    @Builder.Default
    private boolean mfaEnabled = false;

    @Column(name = "account_locked")
    @Builder.Default
    private boolean accountLocked = false;

    @Column(name = "failed_login_attempts")
    @Builder.Default
    private int failedLoginAttempts = 0;

    @Column(name = "created_at", updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    @Column(name = "last_login")
    private Instant lastLogin;

    public enum UserRole {
        ADMIN,
        SOC_ANALYST,
        VIEWER
    }
}
