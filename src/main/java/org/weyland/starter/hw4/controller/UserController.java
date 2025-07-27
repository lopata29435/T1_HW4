package org.weyland.starter.hw4.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.weyland.starter.hw4.model.User;
import org.weyland.starter.hw4.repository.UserRepository;
import org.weyland.starter.hw4.model.Role;
import org.weyland.starter.hw4.model.RoleName;
import org.weyland.starter.hw4.repository.RoleRepository;
import org.springframework.http.ResponseEntity;
import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

@RestController
@RequestMapping("/users")
@Tag(name = "User API")
@SecurityRequirement(name = "BearerAuth")
public class UserController {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Operation(summary = "Получить всех пользователей (только ADMIN)")
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Operation(summary = "Получить свои данные (любой авторизованный)")
    @GetMapping("/me")
    public User getMe(Principal principal) {
        Optional<User> user = userRepository.findByLogin(principal.getName());
        return user.orElseThrow();
    }

    @Operation(summary = "Получить пользователя по id (ADMIN или владелец)")
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasPermission(#id, 'User', 'read')")
    public User getUserById(@PathVariable Long id) {
        return userRepository.findById(id).orElseThrow();
    }

    @Operation(summary = "Изменить роль пользователя (только ADMIN, нельзя менять себе)")
    @PostMapping("/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> changeUserRole(
            @PathVariable Long id,
            @RequestParam RoleName role,
            Principal principal
    ) {
        var userOpt = userRepository.findById(id);
        if (userOpt.isEmpty()) throw new java.util.NoSuchElementException("User not found");
        var user = userOpt.get();
        if (user.getLogin().equals(principal.getName())) {
            throw new IllegalArgumentException("Нельзя менять роль самому себе");
        }
        Role newRole = roleRepository.findByName(role).orElseThrow();
        Set<Role> roles = new HashSet<>();
        roles.add(newRole);
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok("Роль пользователя обновлена");
    }
}
