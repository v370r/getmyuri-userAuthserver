package com.getmyuri.user_auth_service.controller.auth;

import com.getmyuri.user_auth_service.model.auth.AuthenticationRequest;
import com.getmyuri.user_auth_service.model.auth.AuthenticationResponse;
import com.getmyuri.user_auth_service.model.auth.RegistrationRequest;
import com.getmyuri.user_auth_service.service.auth.FirebaseAuthenticationService;
import com.google.firebase.auth.FirebaseAuthException;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.ExecutionException;

@RestController
@RequestMapping("auth")
@RequiredArgsConstructor
@Tag(name = "Authentication")
@Slf4j
public class AuthenticationController {

    private final FirebaseAuthenticationService firebaseAuthService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ResponseEntity<?> postMethodName(@RequestBody @Valid RegistrationRequest request) throws MessagingException, FirebaseAuthException, ExecutionException, InterruptedException {
        log.info("User registration started for email: {}", request.getEmail());
        firebaseAuthService.register(request);
        log.info("User registration successful for email: {}", request.getEmail());
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> postMethodName(@RequestBody @Valid AuthenticationRequest request) throws ExecutionException, InterruptedException {
        log.info("User authentication started for email: {}", request.getEmail());
        AuthenticationResponse response = firebaseAuthService.authenticate(request);
        log.info("User authentication successful for email: {}", request.getEmail());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/activate-account")
    public void confirm(@RequestParam String token, @RequestParam String email) throws MessagingException, ExecutionException, InterruptedException {
        log.info("Account activation started for email: {}", email);
        firebaseAuthService.activateAccount(token, email);
        log.info("Account activation successful for email: {}", email);
    }
}
