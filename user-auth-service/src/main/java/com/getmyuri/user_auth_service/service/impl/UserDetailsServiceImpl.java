package com.getmyuri.user_auth_service.service.impl;

import com.getmyuri.user_auth_service.repository.FirebaseUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.concurrent.ExecutionException;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final FirebaseUserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            return userRepository.findByEmail(username).orElseThrow(
                    () -> new UsernameNotFoundException(String.format("User with email %s not found", username)));
        } catch (ExecutionException | InterruptedException e) {
            throw new UsernameNotFoundException(String.format("User with email %s not found", username));
        }
    }

}
