package org.weyland.starter.hw4.service;

import org.weyland.starter.hw4.model.RefreshToken;
import org.weyland.starter.hw4.model.User;
import org.weyland.starter.hw4.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class TokenService {
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    public RefreshToken createRefreshToken(User user, Instant expiresAt) {
        RefreshToken token = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiresAt(expiresAt)
                .revoked(false)
                .used(false)
                .build();
        return refreshTokenRepository.save(token);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public void revokeToken(RefreshToken token) {
        token.setRevoked(true);
        refreshTokenRepository.save(token);
    }

    @Transactional
    public void markTokenUsed(RefreshToken token) {
        token.setUsed(true);
        refreshTokenRepository.save(token);
    }
} 