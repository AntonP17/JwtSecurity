package com.example.jwtsecurity.service;


import com.example.jwtsecurity.repository.UserRepository;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class OurUserDetailedService implements UserDetailsService {
    private final UserRepository userRepository;

    public OurUserDetailedService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        com.example.jwtsecurity.model.User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        if (!user.isAccountNonLocked()) {
            throw new LockedException("Account is locked");
        }
        return new User(
                user.getUsername(),
                user.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority(user.getRole().name()))
        );
    }

    public void lockUser(String username) {
        com.example.jwtsecurity.model.User user = userRepository.findByUsername(username);
        if (user != null) {
            user.setAccountNonLocked(false);
            userRepository.save(user);
        }
    }

    public void unlockUser(String username) {
        com.example.jwtsecurity.model.User user = userRepository.findByUsername(username);
        if (user != null) {
            user.setAccountNonLocked(true);
            userRepository.save(user);
        }
    }
}
