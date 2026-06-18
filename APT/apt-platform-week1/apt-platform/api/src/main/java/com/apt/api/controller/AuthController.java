package com.apt.api.controller;

import com.apt.api.security.JwtTokenProvider;
import com.apt.core.model.AppUser;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

/**
 * AuthController — handles login and logout for the SOC platform.
 *
 * POST /api/auth/login  → validates credentials, returns a JWT token
 * POST /api/auth/logout → blacklists the current token in Redis
 *
 * The login flow:
 *   1. Client sends { username, password }
 *   2. We pass to AuthenticationManager (which calls UserDetailsService)
 *   3. On success, generate JWT with username + role
 *   4. Return token to client
 *   5. Client stores token and sends it in future requests as:
 *      Authorization: Bearer <token>
 *
 * Note on MFA (Week 3):
 *   If the user has mfaEnabled=true, login returns a partial token with
 *   role="MFA_PENDING", and the client must call /api/auth/verify-totp
 *   with their TOTP code to get a full-access token.
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final StringRedisTemplate redisTemplate;

    // JWT expiry in ms — used to set TTL on Redis blacklist entries
    private static final long TOKEN_EXPIRY_MS = 86_400_000L; // 24 hours

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            // Delegate to Spring Security's authentication mechanism.
            // This calls AptUserDetailsService.loadUserByUsername() under the hood,
            // fetches the user from PostgreSQL, and verifies the BCrypt password.
            Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getUsername(), request.getPassword()
                )
            );

            // Extract the role from the authenticated principal's authorities
            String role = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .findFirst()
                .orElse("VIEWER")
                .replace("ROLE_", "");

            String token = tokenProvider.generateToken(request.getUsername(), role);

            log.info("Successful login for user '{}' with role '{}'", request.getUsername(), role);

            return ResponseEntity.ok(Map.of(
                "token", token,
                "username", request.getUsername(),
                "role", role,
                "expiresIn", TOKEN_EXPIRY_MS
            ));

        } catch (BadCredentialsException e) {
            log.warn("Failed login attempt for user '{}'", request.getUsername());
            // Generic message — never reveal whether username or password was wrong
            return ResponseEntity.status(401).body(Map.of(
                "error", "Invalid credentials"
            ));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            // Blacklist token in Redis with TTL = remaining token lifetime
            // After TTL expires, the entry is automatically removed
            redisTemplate.opsForValue().set(
                "blacklist:" + token,
                "true",
                Duration.ofMillis(TOKEN_EXPIRY_MS)
            );
            log.info("Token blacklisted on logout");
        }
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    // ── Request / Response DTOs ───────────────────────────────────────────────

    @Data
    public static class LoginRequest {
        @NotBlank(message = "Username is required")
        private String username;

        @NotBlank(message = "Password is required")
        private String password;
    }
}
