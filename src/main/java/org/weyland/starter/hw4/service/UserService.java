package org.weyland.starter.hw4.service;

import org.weyland.starter.hw4.model.User;
import org.weyland.starter.hw4.model.Role;
import org.weyland.starter.hw4.model.RoleName;
import org.weyland.starter.hw4.repository.UserRepository;
import org.weyland.starter.hw4.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.Optional;
import java.util.Set;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public Optional<User> findByLogin(String login) {
        return userRepository.findByLogin(login);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public boolean existsByLogin(String login) {
        return userRepository.existsByLogin(login);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    @Transactional
    public User registerUser(String login, String email, String password) {
        Role userRole = roleRepository.findByName(RoleName.USER)
                .orElseThrow(() -> new RuntimeException("Role USER not found"));
        User user = User.builder()
                .login(login)
                .email(email)
                .password(passwordEncoder.encode(password))
                .roles(Set.of(userRole))
                .build();
        return userRepository.save(user);
    }

    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }
} 