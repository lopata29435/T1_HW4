package org.weyland.starter.hw4.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.weyland.starter.hw4.model.User;
import org.weyland.starter.hw4.model.Role;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class JwtService {
    private final Key key;

    public JwtService(@Value("${jwt.secret}") String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String generateAccessToken(User user, long expiresInSeconds) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(user.getId().toString())
                .claim("login", user.getLogin())
                .claim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()))
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(expiresInSeconds)))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public Jws<Claims> parseToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
    }

    public boolean isTokenValid(String token) {
        try {
            parseToken(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public Long getUserId(String token) {
        return Long.valueOf(parseToken(token).getBody().getSubject());
    }

    public Set<String> getRoles(String token) {
        Object roles = parseToken(token).getBody().get("roles");
        if (roles instanceof Set<?>) {
            return ((Set<?>) roles).stream().map(Object::toString).collect(Collectors.toSet());
        }
        return Set.of();
    }

    public Instant getExpiration(String token) {
        Date exp = parseToken(token).getBody().getExpiration();
        return exp.toInstant();
    }
} 