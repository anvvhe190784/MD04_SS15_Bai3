package com.example.course.controller;

import com.example.course.dto.CourseRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class CourseRbacSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Bài 3: Không có Header X-User-Role -> 401 Unauthorized")
    void shouldReturn401WhenNoRoleHeader() throws Exception {
        mockMvc.perform(get("/api/courses"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Bài 3: Header X-User-Role là STUDENT -> GET /api/courses thành công 200 OK")
    void shouldAllowStudentToGetCourses() throws Exception {
        mockMvc.perform(get("/api/courses")
                        .header("X-User-Role", "STUDENT"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    @DisplayName("Bài 3: Header X-User-Role là STUDENT -> POST /api/courses bị từ chối 403 Forbidden")
    void shouldForbidStudentFromCreatingCourse() throws Exception {
        CourseRequest request = new CourseRequest("Advanced Spring", "student");

        mockMvc.perform(post("/api/courses")
                        .header("X-User-Role", "STUDENT")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Bài 3: Header X-User-Role là INSTRUCTOR -> POST /api/courses thành công 201 Created")
    void shouldAllowInstructorToCreateCourse() throws Exception {
        CourseRequest request = new CourseRequest("DevOps & Kubernetes", "instructor");

        mockMvc.perform(post("/api/courses")
                        .header("X-User-Role", "INSTRUCTOR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.title").value("DevOps & Kubernetes"));
    }
}
