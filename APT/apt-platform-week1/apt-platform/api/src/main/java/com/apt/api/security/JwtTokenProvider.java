package com.apt.api.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * JwtTokenProvider — creates, parses, and validates JWT tokens.
 *
 * JWT (JSON Web Token) is how we authenticate API requests without
 * hitting the database on every call. Here's the flow:
 *
 *   1. User POSTs credentials to /api/auth/login
 *   2. We verify password, then call generateToken() here
 *   3. Token is returned to the client and stored (localStorage / memory)
 *   4. Client sends token in every request header:
 *          Authorization: Bearer <token>
 *   5. JwtAuthFilter (next class) intercepts every request,
 *      calls validateToken() here, and sets the SecurityContext
 *
 * The token contains:
 *   - subject: username
 *   - role: ADMIN / SOC_ANALYST / VIEWER
 *   - issued at + expiration timestamps
 *   - signed with HMAC-SHA512 using our 256-bit secret key
 *
 * Security properties:
 *   - Tokens expire after 24h (configurable)
 *   - Logout invalidates the token via Redis blacklist
 *   - Secret key is injected from environment, never in source code
 */
@Slf4j
@Component
public class JwtTokenProvider {

    private final SecretKey signingKey;
    private final long expirationMs;

    public JwtTokenProvider(
        @Value("${app.jwt.secret}") String secret,
        @Value("${app.jwt.expiration-ms}") long expirationMs
    ) {
        // Derive a cryptographically strong key from the configured secret
        // Keys.hmacShaKeyFor requires at least 64 bytes for SHA-512
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.expirationMs = expirationMs;
    }

    /**
     * Generates a signed JWT token for an authenticated user.
     *
     * @param username  the authenticated username (becomes the token subject)
     * @param role      the user's role (embedded as a claim for authorization)
     * @return signed JWT string, ready to send to the client
     */
    public String generateToken(String username, String role) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
            .subject(username)
            .claim("role", role)                    // Custom claim for RBAC
            .issuedAt(now)
            .expiration(expiry)
            .signWith(signingKey, Jwts.SIG.HS512)   // HMAC-SHA512 signature
            .compact();
    }

    /**
     * Extracts the username from a token.
     * Called by JwtAuthFilter on every authenticated request.
     */
    public String getUsernameFromToken(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * Extracts the role claim from a token.
     */
    public String getRoleFromToken(String token) {
        return parseClaims(token).get("role", String.class);
    }

    /**
     * Validates a token — checks signature and expiration.
     *
     * Returns false (instead of throwing) so the filter can cleanly
     * return 401 without a stack trace on every bad request.
     */
    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("JWT token expired for subject: {}", e.getClaims().getSubject());
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported JWT token");
        } catch (MalformedJwtException e) {
            log.warn("Malformed JWT token");
        } catch (SecurityException e) {
            log.warn("Invalid JWT signature");
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims string is empty");
        }
        return false;
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
            .verifyWith(signingKey)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }
}
