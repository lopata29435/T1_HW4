package org.weyland.starter.hw4.service;

import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.weyland.starter.hw4.model.User;
import org.weyland.starter.hw4.model.Role;
import org.weyland.starter.hw4.security.TokenEncryptionService;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class JwtService {

    @Autowired
    private TokenEncryptionService tokenEncryptionService;

    public String generateAccessToken(User user, long expiresInSeconds) {
        Instant now = Instant.now();
        Map<String, Object> claims = new HashMap<>();
        claims.put("login", user.getLogin());
        claims.put("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()));
        claims.put("exp", Date.from(now.plusSeconds(expiresInSeconds)));

        return tokenEncryptionService.createJwe(user.getId().toString(), claims);
    }

    public JWTClaimsSet parseToken(String token) {
        return tokenEncryptionService.parseJwe(token);
    }

    public boolean isTokenValid(String token) {
        try {
            return tokenEncryptionService.validateJwe(token);
        } catch (Exception e) {
            return false;
        }
    }

    public Long getUserId(String token) {
        try {
            String subject = parseToken(token).getSubject();
            return Long.valueOf(subject);
        } catch (Exception e) {
            throw new RuntimeException("Error extracting user ID", e);
        }
    }

    public Set<String> getRoles(String token) {
        try {
            Object roles = parseToken(token).getClaim("roles");
            if (roles instanceof Set<?>) {
                return ((Set<?>) roles).stream().map(Object::toString).collect(Collectors.toSet());
            }
            return Set.of();
        } catch (Exception e) {
            throw new RuntimeException("Error extracting roles", e);
        }
    }

    public Instant getExpiration(String token) {
        try {
            Date exp = parseToken(token).getDateClaim("exp");
            return exp.toInstant();
        } catch (Exception e) {
            throw new RuntimeException("Error extracting expiration time", e);
        }
    }
}
