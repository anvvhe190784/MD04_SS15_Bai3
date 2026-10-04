package com.example.gateway.filter;

import com.example.gateway.config.JwtProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtCourseGatewayFilterTest {

    private static final String SECRET = "9a4f2c8d3b7a1e6f4c8d2e9a7b1c3f5d8a2e4c6b8a1d3f5e7c9b2a4d6f8e1a3c";
    private Key signingKey;

    @Mock
    private GatewayFilterChain chain;

    @Mock
    private ReactiveStringRedisTemplate redisTemplate;

    private JwtCourseGatewayFilter filter;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        signingKey = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setSecret(SECRET);

        filter = new JwtCourseGatewayFilter(jwtProperties, redisTemplate, objectMapper);
    }

    private String createToken(String username, String role, List<String> permissions, String jti, long ttlMs) {
        Date now = new Date();
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .claim("permissions", permissions)
                .setId(jti)
                .claim("jti", jti)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + ttlMs))
                .signWith(signingKey)
                .compact();
    }

    @Test
    @DisplayName("Bài 2: Không có Authorization Header -> Gateway trả 401 Unauthorized")
    void shouldReturn401WhenNoAuthorizationHeader() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(chain);
    }

    @Test
    @DisplayName("Bài 2: Token hết hạn hoặc sai signature -> Gateway trả 401 Unauthorized")
    void shouldReturn401WhenTokenIsInvalidOrExpired() {
        String expiredToken = createToken("student", "STUDENT", List.of("COURSE_READ"), UUID.randomUUID().toString(), -1000L);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + expiredToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(chain);
    }

    @Test
    @DisplayName("Bài 2: Token hợp lệ -> Gateway trích xuất role và gắn header X-User-Role forward xuống Course Service")
    void shouldForwardWithXUserRoleHeaderWhenTokenValid() {
        String token = createToken("student", "STUDENT", List.of("COURSE_READ"), "token-123", 60000L);
        when(redisTemplate.hasKey("blacklist:token-123")).thenReturn(Mono.just(false));
        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain, times(1)).filter(captor.capture());

        ServerWebExchange mutatedExchange = captor.getValue();
        assertThat(mutatedExchange.getRequest().getHeaders().getFirst("X-User-Role")).isEqualTo("STUDENT");
        assertThat(mutatedExchange.getRequest().getHeaders().getFirst("X-User-Permissions")).contains("COURSE_READ");
    }

    @Test
    @DisplayName("Bài 5: Token nằm trong Redis Blacklist -> Gateway chặn đứng trả 401 Unauthorized")
    void shouldReturn401WhenTokenIsBlacklistedInRedis() {
        String token = createToken("student", "STUDENT", List.of("COURSE_READ"), "revoked-jti-1", 60000L);
        when(redisTemplate.hasKey("blacklist:revoked-jti-1")).thenReturn(Mono.just(true));

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(chain);
    }
}
