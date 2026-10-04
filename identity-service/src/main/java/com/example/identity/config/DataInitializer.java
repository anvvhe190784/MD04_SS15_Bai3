package com.example.identity.config;

import com.example.identity.model.User;
import com.example.identity.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@Configuration
public class DataInitializer {

    @Bean
    public CommandLineRunner initData(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (!userRepository.existsByUsername("student")) {
                userRepository.save(new User(
                        "student",
                        passwordEncoder.encode("password"),
                        "STUDENT",
                        Set.of("ROLE_STUDENT", "STUDENT"),
                        Set.of("COURSE_READ")
                ));
            }
            if (!userRepository.existsByUsername("instructor")) {
                userRepository.save(new User(
                        "instructor",
                        passwordEncoder.encode("password"),
                        "INSTRUCTOR",
                        Set.of("ROLE_INSTRUCTOR", "INSTRUCTOR"),
                        Set.of("COURSE_READ", "COURSE_WRITE")
                ));
            }
        };
    }
}
