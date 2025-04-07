package com.example.jwtsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/secured")
public class SecuredController {
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user-resource")
    public String getUserResource() {
        return "User Resource";
    }

    @PreAuthorize("hasRole('MODERATOR')")
    @GetMapping("/moderator-resource")
    public String getModeratorResource() {
        return "Moderator Resource";
    }

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/admin-resource")
    public String getAdminResource() {
        return "Admin Resource";
    }
}
