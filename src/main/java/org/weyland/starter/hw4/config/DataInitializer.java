package org.weyland.starter.hw4.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.weyland.starter.hw4.model.Role;
import org.weyland.starter.hw4.model.RoleName;
import org.weyland.starter.hw4.model.User;
import org.weyland.starter.hw4.repository.RoleRepository;
import org.weyland.starter.hw4.repository.UserRepository;
import java.util.Set;

@Configuration
public class DataInitializer {
    @Bean
    public CommandLineRunner initRolesAndAdmin(
            RoleRepository roleRepository,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            @Value("${admin.login:admin}") String adminLogin,
            @Value("${admin.password:admin}") String adminPassword,
            @Value("${admin.email:admin@admin.com}") String adminEmail
    ) {
        return args -> {
            // Создать роли, если их нет
            for (RoleName roleName : RoleName.values()) {
                roleRepository.findByName(roleName)
                    .orElseGet(() -> roleRepository.save(Role.builder().name(roleName).build()));
            }
            // Создать админа, если его нет
            if (userRepository.findByLogin(adminLogin).isEmpty()) {
                Role adminRole = roleRepository.findByName(RoleName.ADMIN).orElseThrow();
                Role userRole = roleRepository.findByName(RoleName.USER).orElseThrow();
                User admin = User.builder()
                        .login(adminLogin)
                        .email(adminEmail)
                        .password(passwordEncoder.encode(adminPassword))
                        .roles(Set.of(adminRole, userRole))
                        .build();
                userRepository.save(admin);
            }
        };
    }
} 