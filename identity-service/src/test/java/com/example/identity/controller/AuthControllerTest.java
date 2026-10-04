package com.example.identity.controller;

import com.example.identity.dto.LoginRequest;
import com.example.identity.repository.RefreshTokenRepository;
import com.example.identity.repository.UserRepository;
import com.example.identity.service.JwtUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("Bài 1: Login thành công trả về Access Token và Refresh Token, payload chứa đủ sub, role, jti")
    void shouldLoginSuccessfullyAndReturnTokensWithRequiredClaims() throws Exception {
        LoginRequest loginRequest = new LoginRequest("student", "password");

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();

        JsonNode responseJson = objectMapper.readTree(result.getResponse().getContentAsString());
        String accessToken = responseJson.get("accessToken").asText();
        String refreshToken = responseJson.get("refreshToken").asText();

        // Kiểm tra JWT Payload qua JwtUtils (tương tự dán vào jwt.io)
        Claims claims = jwtUtils.getClaims(accessToken);
        assertThat(claims.getSubject()).isEqualTo("student");
        assertThat(claims.get("role")).isEqualTo("STUDENT");
        assertThat(claims.getId()).isNotNull();
        assertThat(claims.get("jti")).isNotNull();

        // Kiểm tra DB refresh_tokens đã lưu bản ghi
        assertThat(refreshTokenRepository.findByToken(refreshToken)).isPresent();
    }

    @Test
    @DisplayName("Bài 1: Login với instructor thành công, role là INSTRUCTOR")
    void shouldLoginInstructorSuccessfully() throws Exception {
        LoginRequest loginRequest = new LoginRequest("instructor", "password");

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode responseJson = objectMapper.readTree(result.getResponse().getContentAsString());
        String accessToken = responseJson.get("accessToken").asText();

        Claims claims = jwtUtils.getClaims(accessToken);
        assertThat(claims.getSubject()).isEqualTo("instructor");
        assertThat(claims.get("role")).isEqualTo("INSTRUCTOR");
        assertThat(claims.getId()).isNotNull();
    }

    @Test
    @DisplayName("Bài 1: Login thất bại với sai password")
    void shouldFailLoginWithWrongPassword() throws Exception {
        LoginRequest loginRequest = new LoginRequest("student", "wrong_password");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }
}
