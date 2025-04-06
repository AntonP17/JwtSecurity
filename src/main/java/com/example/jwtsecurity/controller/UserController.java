package com.example.jwtsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserController {

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String getUserProfile() {
        return"User Profile";
    }

    @PreAuthorize("hasRole('MODERATOR')")
    @GetMapping("/moderator")
    public String getModeratorProfile() {
        return "Moderator Profile";
    }

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/admin")
    public String getAdminProfile() {
        return "Admin Profile";
    }
}
