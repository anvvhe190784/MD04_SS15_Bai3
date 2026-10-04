package com.example.identity.service;

import com.example.identity.dto.LoginRequest;
import com.example.identity.dto.RefreshRequest;
import com.example.identity.dto.TokenResponse;
import com.example.identity.exception.TokenRefreshException;
import com.example.identity.model.RefreshToken;
import com.example.identity.model.User;
import com.example.identity.repository.UserRepository;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.TimeUnit;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final StringRedisTemplate redisTemplate;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtUtils jwtUtils,
                       RefreshTokenService refreshTokenService,
                       StringRedisTemplate redisTemplate) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.redisTemplate = redisTemplate;
    }

    public TokenResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new BadCredentialsException("Invalid username or password"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }

        String accessToken = jwtUtils.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return new TokenResponse(accessToken, refreshToken.getToken());
    }

    @Transactional
    public TokenResponse refreshToken(RefreshRequest request) {
        String requestRefreshToken = request.refreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    // Token Rotation: xóa token cũ để chống replay attack
                    refreshTokenService.deleteByToken(requestRefreshToken);

                    String newAccessToken = jwtUtils.generateAccessToken(user);
                    RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

                    return new TokenResponse(newAccessToken, newRefreshToken.getToken());
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken, "Refresh token is not in database!"));
    }

    public void logout(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            if (jwtUtils.validateToken(token)) {
                String jti = jwtUtils.getJti(token);
                long remainingTtlMs = jwtUtils.getRemainingTtlMs(token);

                if (jti != null && remainingTtlMs > 0) {
                    redisTemplate.opsForValue().set("blacklist:" + jti, "revoked", remainingTtlMs, TimeUnit.MILLISECONDS);
                }
            }
        }
    }
}
