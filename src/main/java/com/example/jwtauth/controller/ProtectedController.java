package com.example.jwtauth.controller;

import com.example.jwtauth.security.UserDetailsImpl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class ProtectedController {

    @GetMapping("/all")
    public String allAccess() {
        return "Public Content: Accessible by anyone.";
    }

    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('OWNER')")
    public ResponseEntity<?> userProfile() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) auth.getPrincipal();

        Map<String, Object> response = new HashMap<>();
        response.clear();
        response.put("id", userDetails.getId());
        response.put("username", userDetails.getUsername());
        response.put("email", userDetails.getEmail());
        response.put("authorities", userDetails.getAuthorities());
        response.put("message", "User profile details fetched successfully.");

        return ResponseEntity.ok(response);
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN') or hasRole('OWNER')")
    public String usersAccess() {
        return "Users Management Dashboard: Accessible by ADMIN and OWNER roles.";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin Board: Accessible only by ADMIN role.";
    }

    @GetMapping("/owner")
    @PreAuthorize("hasRole('OWNER')")
    public String ownerAccess() {
        return "Owner Board: Accessible only by OWNER role.";
    }
}
