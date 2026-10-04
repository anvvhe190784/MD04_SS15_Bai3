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
class CoursePbacSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Bài 6: Quyền duy nhất COURSE_READ -> GET /api/courses thành công 200 OK")
    void shouldAllowUserWithCourseReadPermissionToGetCourses() throws Exception {
        mockMvc.perform(get("/api/courses")
                        .header("X-User-Permissions", "[\"COURSE_READ\"]"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    @DisplayName("Bài 6: Quyền duy nhất COURSE_READ -> POST /api/courses bị từ chối 403 Forbidden")
    void shouldForbidUserWithOnlyCourseReadFromCreatingCourse() throws Exception {
        CourseRequest request = new CourseRequest("Cloud Security", "reader");

        mockMvc.perform(post("/api/courses")
                        .header("X-User-Permissions", "[\"COURSE_READ\"]")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Bài 6: Quyền COURSE_WRITE -> POST /api/courses thành công 201 Created")
    void shouldAllowUserWithCourseWritePermissionToCreateCourse() throws Exception {
        CourseRequest request = new CourseRequest("Advanced Microservices PBAC", "writer");

        mockMvc.perform(post("/api/courses")
                        .header("X-User-Permissions", "[\"COURSE_READ\", \"COURSE_WRITE\"]")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.title").value("Advanced Microservices PBAC"));
    }
}
