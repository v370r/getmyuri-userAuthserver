package com.getmyuri.user_auth_service.config;

import com.getmyuri.user_auth_service.model.role.Role;
import com.getmyuri.user_auth_service.repository.FirebaseRoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.ExecutionException;

@Configuration
public class RoleInitializer {

    @Bean
    public CommandLineRunner initializeRoles(FirebaseRoleRepository roleRepository) {
        return args -> {
            try {
                if (roleRepository.findByName("USER").isEmpty()) {
                    roleRepository.save(Role.builder().name("USER").build());
                    System.out.println("Role 'USER' initialized.");
                } else {
                    System.out.println("Role 'USER' already exists.");
                }
            } catch (ExecutionException | InterruptedException e) {
                e.printStackTrace();
            }
        };
    }
}