package com.example.course.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class CourseHeaderSecurityFilter extends OncePerRequestFilter {

    private final CourseAuthenticationConverter authenticationConverter;

    public CourseHeaderSecurityFilter(CourseAuthenticationConverter authenticationConverter) {
        this.authenticationConverter = authenticationConverter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String roleHeader = request.getHeader("X-User-Role");
        String permissionsHeader = request.getHeader("X-User-Permissions");

        AbstractAuthenticationToken authentication = authenticationConverter.convert(roleHeader, permissionsHeader);
        if (authentication != null) {
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}
