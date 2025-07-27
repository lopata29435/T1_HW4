package org.weyland.starter.hw4.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.weyland.starter.hw4.model.AccessToken;
import org.weyland.starter.hw4.model.User;

import java.util.List;
import java.util.Optional;

@Repository
public interface AccessTokenRepository extends JpaRepository<AccessToken, Long> {
    Optional<AccessToken> findByToken(String token);

    List<AccessToken> findAllByUser(User user);

    @Modifying
    @Query("UPDATE AccessToken a SET a.revoked = true WHERE a.refreshToken.id = :refreshTokenId")
    void revokeAllByRefreshTokenId(Long refreshTokenId);

    @Modifying
    @Query("UPDATE AccessToken a SET a.revoked = true WHERE a.user.id = :userId")
    void revokeAllByUserId(Long userId);

    boolean existsByTokenAndRevokedFalseAndIpAddressAndUserAgent(
        String token,
        String ipAddress,
        String userAgent
    );
}
