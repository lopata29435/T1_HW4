package org.weyland.starter.hw4.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.weyland.starter.hw4.service.UserService;
import org.weyland.starter.hw4.model.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.http.HttpStatus;
import org.weyland.starter.hw4.service.TokenService;
import org.weyland.starter.hw4.service.JwtService;
import org.weyland.starter.hw4.service.AuditService;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.validation.annotation.Validated;
import jakarta.validation.Valid;
import org.weyland.starter.hw4.dto.RegisterRequest;
import org.weyland.starter.hw4.dto.LoginRequest;
import org.weyland.starter.hw4.dto.RefreshRequest;
import org.weyland.starter.hw4.dto.LogoutRequest;
import org.weyland.starter.hw4.dto.IntrospectRequest;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.GrantedAuthority;

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
    private JwtService jwtService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuditService auditService;
    @Value("${jwt.access-token.expiration:900}")
    private long accessTokenExpiration;
    @Value("${jwt.refresh-token.expiration:604800}")
    private long refreshTokenExpiration;

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
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req, HttpServletRequest request) {
        String login = req.getLogin();
        String password = req.getPassword();
        var userOpt = userService.findByLogin(login);
        if (userOpt.isEmpty() || !passwordEncoder.matches(password, userOpt.get().getPassword())) {
            throw new org.springframework.security.authentication.BadCredentialsException("Invalid credentials");
        }
        var user = userOpt.get();
        String accessToken = jwtService.generateAccessToken(user, accessTokenExpiration);
        Instant refreshExp = Instant.now().plusSeconds(refreshTokenExpiration);
        var refreshToken = tokenService.createRefreshToken(user, refreshExp);
        auditService.log(user, "LOGIN", request.getRemoteAddr());
        var resp = new HashMap<String, Object>();
        resp.put("accessToken", accessToken);
        resp.put("refreshToken", refreshToken.getToken());
        return ResponseEntity.ok(resp);
    }

    @Operation(summary = "Обновление access-токена", security = @SecurityRequirement(name = "BearerAuth"))
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody RefreshRequest req, HttpServletRequest request) {
        String refreshTokenValue = req.getRefreshToken();
        var tokenOpt = tokenService.findByToken(refreshTokenValue);
        if (tokenOpt.isEmpty()) {
            throw new org.springframework.security.authentication.BadCredentialsException("Invalid refresh token");
        }
        var token = tokenOpt.get();
        if (token.isRevoked() || token.isUsed() || token.getExpiresAt().isBefore(Instant.now())) {
            throw new org.springframework.security.authentication.BadCredentialsException("Refresh token is not valid");
        }
        var user = token.getUser();
        tokenService.markTokenUsed(token);
        String accessToken = jwtService.generateAccessToken(user, accessTokenExpiration);
        Instant refreshExp = Instant.now().plusSeconds(refreshTokenExpiration);
        var newRefreshToken = tokenService.createRefreshToken(user, refreshExp);
        auditService.log(user, "REFRESH", request.getRemoteAddr());
        var resp = new HashMap<String, Object>();
        resp.put("accessToken", accessToken);
        resp.put("refreshToken", newRefreshToken.getToken());
        return ResponseEntity.ok(resp);
    }

    @Operation(summary = "Отзыв refresh-токена", security = @SecurityRequirement(name = "BearerAuth"))
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@Valid @RequestBody LogoutRequest req, HttpServletRequest request) {
        String refreshTokenValue = req.getRefreshToken();
        var tokenOpt = tokenService.findByToken(refreshTokenValue);
        if (tokenOpt.isEmpty()) {
            throw new org.springframework.security.authentication.BadCredentialsException("Invalid refresh token");
        }
        var token = tokenOpt.get();
        if (token.isRevoked()) {
            throw new IllegalStateException("Token already revoked");
        }
        tokenService.revokeToken(token);
        auditService.log(token.getUser(), "LOGOUT", request.getRemoteAddr());
        return ResponseEntity.ok(Map.of("message", "Token revoked"));
    }

    @Operation(summary = "Introspect access-токена", security = @SecurityRequirement(name = "BearerAuth"))
    @GetMapping("/introspect")
    public ResponseEntity<?> introspect() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || authentication.getPrincipal().equals("anonymousUser")) {
            return ResponseEntity.ok(Map.of("active", false));
        }
        String username = authentication.getName();
        var roles = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        return ResponseEntity.ok(Map.of(
            "active", true,
            "user", username,
            "roles", roles
        ));
    }
} 