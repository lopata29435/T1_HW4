package org.weyland.starter.hw4.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.weyland.starter.hw4.service.UserService;
import org.weyland.starter.hw4.model.User;
import org.weyland.starter.hw4.model.AccessToken;
import org.weyland.starter.hw4.model.RefreshToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.weyland.starter.hw4.service.TokenService;
import org.weyland.starter.hw4.service.AuditService;
import org.weyland.starter.hw4.repository.AccessTokenRepository;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.validation.annotation.Validated;
import jakarta.validation.Valid;
import org.weyland.starter.hw4.dto.*;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

@RestController
@RequestMapping("/auth")
@Tag(name = "Auth API")
@Validated
public class AuthController {
    @Autowired
    private UserService userService;
    @Autowired
    private TokenService tokenService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuditService auditService;
    @Autowired
    private AccessTokenRepository accessTokenRepository;

    @Operation(summary = "Регистрация пользователя")
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
        String login = req.getLogin();
        String email = req.getEmail();
        String password = req.getPassword();
        if (userService.existsByLogin(login)) {
            throw new IllegalArgumentException("Login already exists");
        }
        if (userService.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already exists");
        }
        User user = userService.registerUser(login, email, password);
        return ResponseEntity.ok(Map.of("id", user.getId(), "login", user.getLogin(), "email", user.getEmail()));
    }

    @Operation(summary = "Аутентификация пользователя")
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestBody LoginRequest req,
            HttpServletRequest request
    ) {
        String login = req.getLogin();
        String password = req.getPassword();

        var userOpt = userService.findByLogin(login);
        if (userOpt.isEmpty() || !passwordEncoder.matches(password, userOpt.get().getPassword())) {
            throw new org.springframework.security.authentication.BadCredentialsException("Invalid credentials");
        }

        var user = userOpt.get();
        String ipAddress = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        AccessToken accessToken = tokenService.createAccessToken(user, ipAddress, userAgent, null);
        RefreshToken refreshToken = tokenService.createRefreshToken(user, ipAddress, userAgent, null);

        auditService.log(user, "LOGIN", ipAddress);

        return ResponseEntity.ok(Map.of(
                "accessToken", accessToken.getToken(),
                "refreshToken", refreshToken.getToken()
        ));
    }

    @Operation(summary = "Обновление access-токена", security = @SecurityRequirement(name = "BearerAuth"))
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(
            @Valid @RequestBody RefreshRequest req,
            HttpServletRequest request
    ) {
        String refreshTokenValue = req.getRefreshToken();
        String ipAddress = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        var tokenOpt = tokenService.findByToken(refreshTokenValue);
        if (tokenOpt.isEmpty()) {
            throw new org.springframework.security.authentication.BadCredentialsException("Invalid refresh token");
        }

        var refreshToken = tokenOpt.get();

        if (!refreshToken.getIpAddress().equals(ipAddress) ||
                !refreshToken.getUserAgent().equals(userAgent)) {
            throw new org.springframework.security.authentication.BadCredentialsException("Token binding mismatch");
        }

        if (refreshToken.isRevoked() || refreshToken.isUsed()) {
            tokenService.revokeAllUserTokens(refreshToken.getUser().getId());
            throw new org.springframework.security.authentication.BadCredentialsException("Refresh token has been revoked");
        }

        AccessToken newAccessToken = tokenService.createAccessToken(
                refreshToken.getUser(),
                ipAddress,
                userAgent,
                null
        );

        tokenService.markTokenUsed(refreshToken);

        RefreshToken newRefreshToken = tokenService.createRefreshToken(
                refreshToken.getUser(),
                ipAddress,
                userAgent,
                null
        );

        tokenService.revokeAccessTokensByRefreshToken(refreshToken.getId());

        return ResponseEntity.ok(Map.of(
                "accessToken", newAccessToken.getToken(),
                "refreshToken", newRefreshToken.getToken()
        ));
    }

    @Operation(summary = "Выход из системы", security = @SecurityRequirement(name = "BearerAuth"))
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @Valid @RequestBody LogoutRequest req,
            HttpServletRequest request
    ) {
        String refreshTokenValue = req.getRefreshToken();
        String ipAddress = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        var tokenOpt = tokenService.findByToken(refreshTokenValue);

        if (tokenOpt.isPresent()) {
            var refreshToken = tokenOpt.get();

            if (!refreshToken.getIpAddress().equals(ipAddress) ||
                !refreshToken.getUserAgent().equals(userAgent)) {
                throw new org.springframework.security.authentication.BadCredentialsException("Token binding mismatch");
            }

            tokenService.revokeAllUserTokens(refreshToken.getUser().getId());
            auditService.log(refreshToken.getUser(), "LOGOUT", ipAddress);
        }

        return ResponseEntity.ok(Map.of("message", "Successfully logged out"));
    }

    @Operation(summary = "Проверка токена", security = @SecurityRequirement(name = "BearerAuth"))
    @GetMapping("/introspect")
    public ResponseEntity<?> introspect(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.ok(Map.of("active", false, "error", "Missing or invalid Authorization header"));
        }

        String accessTokenValue = authHeader.substring(7);
        String ipAddress = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        boolean isValid = tokenService.validateAccessToken(
            accessTokenValue,
            ipAddress,
            userAgent,
            null
        );

        if (isValid) {
            var tokenOpt = accessTokenRepository.findByToken(accessTokenValue);
            if (tokenOpt.isPresent()) {
                AccessToken token = tokenOpt.get();
                User user = token.getUser();
                return ResponseEntity.ok(Map.of(
                    "active", true,
                    "userId", user.getId(),
                    "login", user.getLogin(),
                    "email", user.getEmail(),
                    "roles", user.getRoles().stream().map(r -> r.getName().name()).toList(),
                    "exp", token.getExpiresAt().getEpochSecond()
                ));
            }
        }

        return ResponseEntity.ok(Map.of("active", false));
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}
