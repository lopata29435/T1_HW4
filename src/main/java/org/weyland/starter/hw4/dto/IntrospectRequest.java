package org.weyland.starter.hw4.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class IntrospectRequest {
    @NotBlank
    private String accessToken;
} 