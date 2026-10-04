package com.example.course.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

@Component
public class CourseAuthenticationConverter {

    private final ObjectMapper objectMapper;

    public CourseAuthenticationConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public AbstractAuthenticationToken convert(String roleHeader, String permissionsHeader) {
        if (!StringUtils.hasText(roleHeader) && !StringUtils.hasText(permissionsHeader)) {
            return null;
        }

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        // 1. Map role từ header X-User-Role (Bài 3)
        if (StringUtils.hasText(roleHeader)) {
            authorities.add(new SimpleGrantedAuthority(roleHeader.trim()));
            if (!roleHeader.trim().startsWith("ROLE_")) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + roleHeader.trim()));
            }
        }

        // 2. Map permissions từ header X-User-Permissions JSON (Bài 6)
        if (StringUtils.hasText(permissionsHeader)) {
            try {
                List<String> perms = objectMapper.readValue(permissionsHeader, new TypeReference<List<String>>() {});
                for (String perm : perms) {
                    if (StringUtils.hasText(perm)) {
                        authorities.add(new SimpleGrantedAuthority(perm.trim()));
                    }
                }
            } catch (Exception ignored) {
            }
        }

        String principal = StringUtils.hasText(roleHeader) ? roleHeader.trim().toLowerCase() : "authenticated-user";
        return new UsernamePasswordAuthenticationToken(principal, null, authorities);
    }
}
