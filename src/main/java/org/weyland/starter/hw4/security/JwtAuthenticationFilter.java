package org.weyland.starter.hw4.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.weyland.starter.hw4.model.AccessToken;
import org.weyland.starter.hw4.repository.AccessTokenRepository;
import org.weyland.starter.hw4.repository.UserRepository;
import org.weyland.starter.hw4.service.TokenService;

import java.io.IOException;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private TokenService tokenService;

    @Autowired
    private AccessTokenRepository accessTokenRepository;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String encryptedToken = authHeader.substring(7);
        final String ipAddress = getClientIp(request);
        final String userAgent = request.getHeader("User-Agent");
        final String fingerprint = request.getHeader("X-Fingerprint");

        if (tokenService.validateAccessToken(encryptedToken, ipAddress, userAgent, fingerprint)) {
            Optional<AccessToken> accessTokenOpt = accessTokenRepository.findByToken(encryptedToken);
            if (accessTokenOpt.isPresent()) {
                AccessToken accessToken = accessTokenOpt.get();

                Long userId = accessToken.getUser().getId();
                var userOpt = userRepository.findById(userId);
                if (userOpt.isEmpty()) {
                    filterChain.doFilter(request, response);
                    return;
                }

                UserDetails userDetails = userDetailsService.loadUserByUsername(
                    userOpt.get().getLogin()
                );

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
                );

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}
