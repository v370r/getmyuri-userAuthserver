package com.getmyuri.user_auth_service.controller;

import com.getmyuri.user_auth_service.dto.LoginRequest;
import com.getmyuri.user_auth_service.dto.LoginResponse;
import com.getmyuri.user_auth_service.dto.RegisterRequest;
import com.getmyuri.user_auth_service.model.user.User;
import com.getmyuri.user_auth_service.model.role.Role;
import com.getmyuri.user_auth_service.repository.RoleRepository;
import com.getmyuri.user_auth_service.repository.UserRepository;
import com.getmyuri.user_auth_service.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.List;
import java.time.LocalDate; // Assuming dateOfBirth is not part of registration for now

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Error: Email is already in use!");
        }

        User user = User.builder()
                .firstname(registerRequest.getFirstname())
                .lastname(registerRequest.getLastname())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .accountLocked(false)
                .enabled(true) // Or false if email verification is needed
                .dateOfBirth(registerRequest.getDateOfBirth()) // Added if present in DTO
                .build();

        // Assign default role "USER"
        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Error: Role USER is not found."));
        user.setRoles(List.of(userRole));

        userRepository.save(user);

        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully!");
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
        );

        User user = (User) authentication.getPrincipal();
        String jwtToken = jwtService.generateToken(user);

        return ResponseEntity.ok(new LoginResponse(jwtToken, user.getEmail(), user.getRoles().stream().map(Role::getName).toList()));
    }
}
