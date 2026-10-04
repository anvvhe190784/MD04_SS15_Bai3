package com.example.course.controller;

import com.example.course.dto.CourseRequest;
import com.example.course.model.Course;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/api/courses")
public class CourseController {

    private final List<Course> courses = new CopyOnWriteArrayList<>();
    private final AtomicLong idGenerator = new AtomicLong(2);

    public CourseController() {
        courses.add(new Course(1L, "Spring Boot Microservices", "instructor"));
        courses.add(new Course(2L, "Spring Cloud Gateway & Security", "instructor"));
    }

    @GetMapping
    @PreAuthorize("hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR') or hasAuthority('COURSE_READ')")
    public ResponseEntity<List<Course>> getAllCourses() {
        return ResponseEntity.ok(courses);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('INSTRUCTOR') or hasAuthority('COURSE_WRITE')")
    public ResponseEntity<Course> createCourse(@RequestBody CourseRequest request) {
        Course course = new Course(idGenerator.incrementAndGet(), request.title(), request.instructor());
        courses.add(course);
        return ResponseEntity.status(HttpStatus.CREATED).body(course);
    }
}
