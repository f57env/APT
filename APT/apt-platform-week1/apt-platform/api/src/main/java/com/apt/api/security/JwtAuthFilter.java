package com.apt.api.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JwtAuthFilter — intercepts every HTTP request before it reaches a controller.
 *
 * The filter chain in Spring Security runs in order. This filter sits
 * before UsernamePasswordAuthenticationFilter, so JWT auth takes
 * priority over form-based login.
 *
 * Flow for a typical API request:
 *   Request arrives → JwtAuthFilter runs
 *     → No token?          → chain.doFilter (Spring rejects if endpoint requires auth)
 *     → Token blacklisted? → 401 Unauthorized
 *     → Token invalid?     → 401 Unauthorized
 *     → Token valid?       → Set SecurityContext → chain.doFilter → Controller runs
 *
 * Redis blacklist:
 *   On logout, we store the token in Redis with a TTL matching the token's
 *   remaining lifetime. This filter checks Redis on every request to catch
 *   logged-out tokens before they expire naturally.
 *   Key format: "blacklist:{tokenString}"
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;
    private final StringRedisTemplate redisTemplate;

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {

        String token = extractToken(request);

        if (StringUtils.hasText(token)) {

            // Check if this token has been explicitly invalidated (logout)
            if (isBlacklisted(token)) {
                log.warn("Rejected blacklisted token from {}", request.getRemoteAddr());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token has been invalidated");
                return;
            }

            if (tokenProvider.validateToken(token)) {
                String username = tokenProvider.getUsernameFromToken(token);
                String role     = tokenProvider.getRoleFromToken(token);

                // Spring Security requires a "ROLE_" prefix on authority names
                List<SimpleGrantedAuthority> authorities =
                    List.of(new SimpleGrantedAuthority("ROLE_" + role));

                // Create an authenticated token and store it in the SecurityContext
                // This is what @PreAuthorize("hasRole('ADMIN')") checks against
                UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(username, null, authorities);

                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("Authenticated user '{}' with role '{}' for {}",
                    username, role, request.getRequestURI());
            } else {
                log.warn("Invalid JWT token from {}", request.getRemoteAddr());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extracts the Bearer token from the Authorization header.
     * Returns null if the header is missing or malformed.
     */
    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
            return header.substring(7); // Remove "Bearer " prefix
        }
        return null;
    }

    private boolean isBlacklisted(String token) {
        return Boolean.TRUE.equals(
            redisTemplate.hasKey("blacklist:" + token)
        );
    }
}
