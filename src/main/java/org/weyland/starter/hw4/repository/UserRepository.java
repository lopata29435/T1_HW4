package org.weyland.starter.hw4.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.weyland.starter.hw4.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByLogin(String login);
    Optional<User> findByEmail(String email);
    boolean existsByLogin(String login);
    boolean existsByEmail(String email);
} 