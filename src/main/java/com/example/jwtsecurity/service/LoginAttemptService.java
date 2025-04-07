package com.example.jwtsecurity.service;

import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginAttemptService {
    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_MINUTES = 15;
    private final ConcurrentHashMap<String, Integer> loginAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lockoutTimes = new ConcurrentHashMap<>();

    public void loginSucceeded(String username) {
        loginAttempts.remove(username);
        lockoutTimes.remove(username);
    }

    public void loginFailed(String username) {
        int attempts = loginAttempts.getOrDefault(username, 0);
        if (attempts < MAX_ATTEMPTS) {
            loginAttempts.put(username, attempts + 1);
        }
        if (attempts + 1 >= MAX_ATTEMPTS) {
            lockAccount(username);
        }
    }

    public boolean isLocked(String username) {
        Long lockoutTime = lockoutTimes.get(username);
        if (lockoutTime == null) {
            return false;
        }
        return System.currentTimeMillis() < lockoutTime;
    }

    private void lockAccount(String username) {
        long lockoutTime = System.currentTimeMillis() + LOCKOUT_DURATION_MINUTES * 60 * 1000;
        lockoutTimes.put(username, lockoutTime);
    }
}
