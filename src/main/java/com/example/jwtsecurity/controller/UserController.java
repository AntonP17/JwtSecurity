package com.example.jwtsecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserController {

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public ResponseEntity<String> getUserProfile() {
        return ResponseEntity.ok("User Profile");
    }

    @PreAuthorize("hasRole('MODERATOR')")
    @GetMapping("/moderator")
    public ResponseEntity<String> getModeratorProfile() {
        return ResponseEntity.ok("Moderator Profile");
    }

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/admin")
    public ResponseEntity<String> getAdminProfile() {
        return ResponseEntity.ok("Admin Profile");
    }

}
