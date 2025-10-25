package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    private final SecretKey signingKey;
    private final long jwtExpirationMs;
    private final String jwtIssuer;

    // SECURITY FIX: Use strong secret from environment variables and set short TTL
    public JwtService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.expiration-ms:900000}") long jwtExpirationMs, // 15 minutes default
            @Value("${app.jwt.issuer:owasp-api-lab}") String jwtIssuer) {
        
        // SECURITY FIX: Use proper key generation instead of raw string
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes());
        this.jwtExpirationMs = jwtExpirationMs;
        this.jwtIssuer = jwtIssuer;
    }

    public String issue(String subject, Map<String, Object> claims) {
        // SECURITY FIX: Include issuer, audience, and short expiration
        return Jwts.builder()
                .setSubject(subject)
                .setIssuer(jwtIssuer)
                .setAudience("owasp-api-users")
                .addClaims(claims)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusMillis(jwtExpirationMs)))
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims parse(String token) {
        // SECURITY FIX: Strict validation with issuer and audience checks
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .requireIssuer(jwtIssuer)
                .requireAudience("owasp-api-users")
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token) {
        try {
            parse(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }
}