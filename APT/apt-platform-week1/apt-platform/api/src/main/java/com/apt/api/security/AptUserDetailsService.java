package com.apt.api.security;

import com.apt.core.model.AppUser;
import com.apt.api.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * AptUserDetailsService — bridges Spring Security with our PostgreSQL users table.
 *
 * Spring Security calls loadUserByUsername() during the authentication process.
 * We fetch the user from PostgreSQL and wrap them in Spring's UserDetails format
 * so the framework can verify the BCrypt password and check account status.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AptUserDetailsService implements UserDetailsService {

    private final AppUserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = userRepository.findByUsername(username)
            .orElseThrow(() -> {
                log.warn("User not found: {}", username);
                return new UsernameNotFoundException("User not found: " + username);
            });

        if (user.isAccountLocked()) {
            log.warn("Locked account login attempt: {}", username);
            throw new org.springframework.security.authentication
                .LockedException("Account is locked");
        }

        return User.builder()
            .username(user.getUsername())
            .password(user.getPasswordHash())  // BCrypt hash from DB
            .authorities(List.of(
                new SimpleGrantedAuthority("ROLE_" + user.getRole().name())
            ))
            .accountLocked(user.isAccountLocked())
            .build();
    }
}
