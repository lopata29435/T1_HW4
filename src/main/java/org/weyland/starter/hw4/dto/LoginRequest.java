package org.weyland.starter.hw4.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {
    @NotBlank
    private String login;
    @NotBlank
    private String password;
} 