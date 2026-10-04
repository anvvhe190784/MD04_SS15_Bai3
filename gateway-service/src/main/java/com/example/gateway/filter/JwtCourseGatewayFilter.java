package com.example.gateway.filter;

import com.example.gateway.config.JwtProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Collection;

@Component
public class JwtCourseGatewayFilter implements GlobalFilter, Ordered {

    private final Key signingKey;
    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public JwtCourseGatewayFilter(JwtProperties jwtProperties,
                                  @Autowired(required = false) ReactiveStringRedisTemplate redisTemplate,
                                  ObjectMapper objectMapper) {
        this.signingKey = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // Chỉ chặn và kiểm tra các request tới /api/courses/**
        if (!path.startsWith("/api/courses")) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.hasText(authHeader) || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);
        Claims claims;
        try {
            claims = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException | IllegalArgumentException e) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }

        // Bài 5: Kiểm tra Redis blacklist nếu có redisTemplate
        String jti = claims.getId();
        if (jti == null) {
            jti = (String) claims.get("jti");
        }

        if (redisTemplate != null && StringUtils.hasText(jti)) {
            return redisTemplate.hasKey("blacklist:" + jti)
                    .defaultIfEmpty(false)
                    .flatMap(isBlacklisted -> {
                        if (Boolean.TRUE.equals(isBlacklisted)) {
                            return onError(exchange, HttpStatus.UNAUTHORIZED);
                        }
                        return proceedWithClaims(exchange, chain, claims);
                    });
        }

        return proceedWithClaims(exchange, chain, claims);
    }

    private Mono<Void> proceedWithClaims(ServerWebExchange exchange, GatewayFilterChain chain, Claims claims) {
        ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate();

        // Trích xuất role và gắn header X-User-Role (Bài 2 & Bài 3)
        Object roleObj = claims.get("role");
        if (roleObj != null) {
            requestBuilder.header("X-User-Role", roleObj.toString());
        }

        // Trích xuất permissions và gắn header X-User-Permissions JSON (Bài 6)
        Object permissionsObj = claims.get("permissions");
        if (permissionsObj instanceof Collection<?> perms) {
            try {
                String permsJson = objectMapper.writeValueAsString(perms);
                requestBuilder.header("X-User-Permissions", permsJson);
            } catch (JsonProcessingException ignored) {
            }
        }

        return chain.filter(exchange.mutate().request(requestBuilder.build()).build());
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
