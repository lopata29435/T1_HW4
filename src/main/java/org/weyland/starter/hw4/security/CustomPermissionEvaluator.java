package org.weyland.starter.hw4.security;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.weyland.starter.hw4.model.User;
import org.weyland.starter.hw4.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import java.io.Serializable;

@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {
    @Autowired
    private UserRepository userRepository;
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (targetDomainObject instanceof User user) {
            String login = authentication.getName();
            return user.getLogin().equals(login);
        }
        return false;
    }
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if ("User".equals(targetType) && targetId instanceof Long userId) {
            String login = authentication.getName();
            return userRepository.findById(userId)
                .map(user -> user.getLogin().equals(login))
                .orElse(false);
        }
        return false;
    }
} 