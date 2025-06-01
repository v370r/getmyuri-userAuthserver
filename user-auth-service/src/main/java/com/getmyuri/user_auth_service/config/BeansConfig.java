package com.getmyuri.user_auth_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class BeansConfig {

    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) { // passwordEncoder is the bean instance
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(); // Initialize DaoAuthenticationProvider
        authProvider.setUserDetailsService(userDetailsService); // Set UserDetailsService
        authProvider.setPasswordEncoder(passwordEncoder); // Correct: use the injected PasswordEncoder bean
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
