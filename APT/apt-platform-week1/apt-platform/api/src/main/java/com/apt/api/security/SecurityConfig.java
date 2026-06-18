package com.apt.api.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * SecurityConfig — the central security configuration for the APT platform.
 *
 * Key design decisions:
 *
 * 1. STATELESS sessions:
 *    JWT auth means we don't need server-side sessions. Every request
 *    carries its own credentials in the Authorization header.
 *    This allows horizontal scaling — any app instance handles any request.
 *
 * 2. RBAC at two levels:
 *    a) URL-level: rules below restrict which roles can hit which paths
 *    b) Method-level: @PreAuthorize on service methods for fine-grained control
 *
 * 3. CSRF disabled:
 *    CSRF attacks rely on browsers automatically sending session cookies.
 *    Since we use JWT (not cookies), CSRF is not a relevant threat here.
 *    If you ever switch to cookie-based auth, re-enable CSRF.
 *
 * 4. BCrypt password hashing:
 *    Strength factor 12 = ~300ms per hash on modern hardware.
 *    This is slow enough to deter brute force but fast enough for login.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity          // Enables @PreAuthorize on service methods
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF — we use JWT, not cookies
            .csrf(AbstractHttpConfigurer::disable)

            // Enable CORS for the React frontend
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))

            // Stateless — no HTTP session created or used
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // ── URL-level access rules ─────────────────────────────────────
            .authorizeHttpRequests(auth -> auth

                // Public endpoints — no token required
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()

                // WebSocket handshake — authenticated via token in URL param
                .requestMatchers("/ws/**").permitAll()

                // Alert management — any authenticated user can view
                .requestMatchers(HttpMethod.GET, "/api/alerts/**").hasAnyRole(
                    "ADMIN", "SOC_ANALYST", "VIEWER")

                // Alert triage (update status) — analysts and admins only
                .requestMatchers(HttpMethod.PATCH, "/api/alerts/**").hasAnyRole(
                    "ADMIN", "SOC_ANALYST")

                // Manual response trigger — analysts and admins only
                .requestMatchers("/api/response/**").hasAnyRole(
                    "ADMIN", "SOC_ANALYST")

                // Entity profiles and MITRE data — any authenticated user
                .requestMatchers(HttpMethod.GET, "/api/entities/**").hasAnyRole(
                    "ADMIN", "SOC_ANALYST", "VIEWER")
                .requestMatchers(HttpMethod.GET, "/api/mitre/**").hasAnyRole(
                    "ADMIN", "SOC_ANALYST", "VIEWER")

                // User management — ADMIN only
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/actuator/**").hasRole("ADMIN")

                // Everything else requires authentication
                .anyRequest().authenticated()
            )

            // Insert our JWT filter BEFORE Spring's username/password filter
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * CORS — allows the React dashboard (on port 3000) to call our API (port 8080).
     * In production, replace localhost:3000 with your actual frontend domain.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(
            "http://localhost:3000",   // React dev server
            "http://localhost:5173"    // Vite dev server (alternative)
        ));
        config.setAllowedMethods(List.of("GET", "POST", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
        config.setExposedHeaders(List.of("Authorization"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * BCryptPasswordEncoder with strength 12.
     * Used to hash passwords on registration and verify on login.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * AuthenticationManager — used by the login controller to authenticate credentials.
     */
    @Bean
    public AuthenticationManager authenticationManager(
        AuthenticationConfiguration config
    ) throws Exception {
        return config.getAuthenticationManager();
    }
}
