package org.weyland.starter.hw4.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.weyland.starter.hw4.model.RefreshToken;
import org.weyland.starter.hw4.model.User;

import java.util.Optional;
import java.util.List;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    List<RefreshToken> findByUser(User user);
} 