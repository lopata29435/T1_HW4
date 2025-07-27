package org.weyland.starter.hw4.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.weyland.starter.hw4.model.AuditLog;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
} 