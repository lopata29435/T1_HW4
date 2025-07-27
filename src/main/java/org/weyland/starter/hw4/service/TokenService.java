package org.weyland.starter.hw4.service;

import com.nimbusds.jwt.JWTClaimsSet;
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
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

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
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "access");
        claims.put("userId", user.getId());
        claims.put("roles", user.getRoles().stream().map(r -> r.getName().name()).toList());
        claims.put("exp", Date.from(Instant.now().plusSeconds(900))); // 15 минут
        claims.put("ip", ipAddress);
        claims.put("ua", userAgent);
        if (fingerprint != null) {
            claims.put("fp", fingerprint);
        }

        String jweToken = tokenEncryptionService.createJwe(user.getLogin(), claims);

        AccessToken token = AccessToken.builder()
                .user(user)
                .token(jweToken)
                .roles(new java.util.HashSet<>(user.getRoles()))
                .expiresAt(Instant.now().plusSeconds(900)) // 15 минут
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .fingerprint(fingerprint)
                .revoked(false)
                .build();

        return accessTokenRepository.save(token);
    }

    @Transactional
    public RefreshToken createRefreshToken(User user, String ipAddress, String userAgent, String fingerprint) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh");
        claims.put("userId", user.getId());
        claims.put("exp", Date.from(Instant.now().plusSeconds(604800))); // 7 дней
        claims.put("ip", ipAddress);
        claims.put("ua", userAgent);
        if (fingerprint != null) {
            claims.put("fp", fingerprint);
        }

        String jweToken = tokenEncryptionService.createJwe(user.getLogin(), claims);

        RefreshToken token = RefreshToken.builder()
                .user(user)
                .token(jweToken)
                .expiresAt(Instant.now().plusSeconds(604800)) // 7 дней
                .revoked(false)
                .used(false)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .fingerprint(fingerprint)
                .build();

        return refreshTokenRepository.save(token);
    }

    @Transactional
    public boolean validateAccessToken(String jweToken, String ipAddress, String userAgent, String fingerprint) {
        try {
            if (!tokenEncryptionService.validateJwe(jweToken)) {
                return false;
            }

            JWTClaimsSet claims = tokenEncryptionService.parseJwe(jweToken);

            if (!"access".equals(claims.getStringClaim("type"))) {
                return false;
            }

            Date expiration = claims.getDateClaim("exp");
            if (expiration != null && expiration.before(new Date())) {
                return false;
            }

            Optional<AccessToken> tokenOpt = accessTokenRepository.findByToken(jweToken);
            if (tokenOpt.isEmpty() || tokenOpt.get().isRevoked()) {
                return false;
            }

            if (ipAddress != null && !ipAddress.equals(claims.getStringClaim("ip"))) {
                return false;
            }

            if (userAgent != null && !userAgent.equals(claims.getStringClaim("ua"))) {
                return false;
            }

            if (fingerprint != null) {
                String tokenFingerprint = claims.getStringClaim("fp");
                if (tokenFingerprint != null && !fingerprint.equals(tokenFingerprint)) {
                    return false;
                }
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


    public Long extractUserId(String jweToken) {
        try {
            JWTClaimsSet claims = tokenEncryptionService.parseJwe(jweToken);
            return claims.getLongClaim("userId");
        } catch (Exception e) {
            throw new RuntimeException("Error extracting user ID from token", e);
        }
    }

    public String extractUsername(String jweToken) {
        try {
            JWTClaimsSet claims = tokenEncryptionService.parseJwe(jweToken);
            return claims.getSubject();
        } catch (Exception e) {
            throw new RuntimeException("Error extracting username from token", e);
        }
    }
}
