package org.weyland.starter.hw4.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.weyland.starter.hw4.model.AccessToken;
import org.weyland.starter.hw4.model.RefreshToken;
import org.weyland.starter.hw4.model.User;
import org.weyland.starter.hw4.repository.AccessTokenRepository;
import org.weyland.starter.hw4.repository.RefreshTokenRepository;
import org.weyland.starter.hw4.security.TokenEncryptionService;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
public class TokenService {
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private AccessTokenRepository accessTokenRepository;

    @Autowired
    private TokenEncryptionService tokenEncryptionService;

    @Transactional
    public AccessToken createAccessToken(User user, String ipAddress, String userAgent, String fingerprint) {
        String rawToken = UUID.randomUUID().toString();
        String encryptedToken = tokenEncryptionService.encryptToken(rawToken);

        AccessToken token = AccessToken.builder()
                .user(user)
                .token(encryptedToken)
                .roles(new java.util.HashSet<>(user.getRoles()))
                .expiresAt(Instant.now().plusSeconds(900))
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .fingerprint(fingerprint)
                .revoked(false)
                .build();

        return accessTokenRepository.save(token);
    }

    @Transactional
    public RefreshToken createRefreshToken(User user, String ipAddress, String userAgent, String fingerprint) {
        String rawToken = UUID.randomUUID().toString();
        String encryptedToken = tokenEncryptionService.encryptToken(rawToken);

        RefreshToken token = RefreshToken.builder()
                .user(user)
                .token(encryptedToken)
                .expiresAt(Instant.now().plusSeconds(604800))
                .revoked(false)
                .used(false)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .fingerprint(fingerprint)
                .build();

        return refreshTokenRepository.save(token);
    }

    @Transactional
    public boolean validateAccessToken(String encryptedToken, String ipAddress, String userAgent, String fingerprint) {
        try {
            String decryptedToken = tokenEncryptionService.decryptToken(encryptedToken);

            Optional<AccessToken> tokenOpt = accessTokenRepository.findByToken(encryptedToken);
            if (tokenOpt.isEmpty()) {
                return false;
            }

            AccessToken token = tokenOpt.get();

            if (token.isRevoked()) {
                return false;
            }

            if (!token.getExpiresAt().isAfter(Instant.now())) {
                return false;
            }

            return true;
        } catch (Exception e) {
            return false;
        }
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

    @Transactional
    public void revokeAllUserTokens(Long userId) {
        accessTokenRepository.revokeAllByUserId(userId);
        refreshTokenRepository.revokeAllByUserId(userId);
    }

    @Transactional
    public void revokeAccessTokensByRefreshToken(Long refreshTokenId) {
        accessTokenRepository.revokeAllByRefreshTokenId(refreshTokenId);
    }
}
