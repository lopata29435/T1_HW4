package org.weyland.starter.hw4.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.weyland.starter.hw4.model.Role;
import org.weyland.starter.hw4.model.RoleName;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleName name);
} 