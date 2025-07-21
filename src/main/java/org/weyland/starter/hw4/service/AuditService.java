package org.weyland.starter.hw4.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.weyland.starter.hw4.model.AuditLog;
import org.weyland.starter.hw4.model.User;
import org.weyland.starter.hw4.repository.AuditLogRepository;
import java.time.Instant;

@Service
public class AuditService {
    @Autowired
    private AuditLogRepository auditLogRepository;

    public void log(User user, String action, String ipAddress) {
        AuditLog log = AuditLog.builder()
                .user(user)
                .action(action)
                .ipAddress(ipAddress)
                .timestamp(Instant.now())
                .build();
        auditLogRepository.save(log);
    }
} 