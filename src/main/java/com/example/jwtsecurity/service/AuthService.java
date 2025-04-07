package com.example.jwtsecurity.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final AuthenticationManager authenticationManager;

    private final JWTUtils jwtUtils;
    private final OurUserDetailedService userDetailsService;
    private final LoginAttemptService loginAttemptService;

    @Autowired
    public AuthService(AuthenticationManager authenticationManager, JWTUtils jwtUtils, OurUserDetailedService userDetailsService, LoginAttemptService loginAttemptService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.userDetailsService = userDetailsService;
        this.loginAttemptService = loginAttemptService;
    }

    public String authenticateUser(String username, String password) {
        if (loginAttemptService.isLocked(username)) {
            throw new LockedException("Account is locked");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        if (authentication.isAuthenticated()) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            loginAttemptService.loginSucceeded(username);
            return jwtUtils.generateToken(userDetails);
        } else {
            loginAttemptService.loginFailed(username);
            throw new RuntimeException("Invalid credentials");
        }
    }
}
