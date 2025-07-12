package com.getmyuri.user_auth_service.controller.auth;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.getmyuri.user_auth_service.model.auth.AuthenticationRequest;
import com.getmyuri.user_auth_service.model.auth.AuthenticationResponse;
// import com.getmyuri.user_auth_service.model.auth.RefreshTokenRequest; // Removed
import com.getmyuri.user_auth_service.model.auth.RegistrationRequest;
import com.getmyuri.user_auth_service.service.auth.AuthenticationService;
import com.getmyuri.user_auth_service.service.JwtService; // Added import for JwtService
// import com.getmyuri.user_auth_service.service.RefreshTokenService; // Removed

import io.jsonwebtoken.JwtException; // Added import for JwtException
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpHeaders; // Added import for HttpHeaders

@RestController
@RequestMapping("auth")
@RequiredArgsConstructor
@Tag(name = "Authentication")
public class AuthenticationController {

    private final AuthenticationService authService;
    private final JwtService jwtService;
    // private final RefreshTokenService refreshTokenService; // Removed RefreshTokenService

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ResponseEntity<?> postMethodName(@RequestBody @Valid RegistrationRequest request) throws MessagingException {
        authService.register(request);
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> postMethodName(@RequestBody @Valid AuthenticationRequest request) {
        return ResponseEntity.ok(authService.authenticate(request));
    }

    @GetMapping("/activate-account")
    public void confirm(@RequestParam String token, @RequestParam String email) throws MessagingException {
        authService.activateAccount(token, email);
    }

    /** 200 → OK, 401 → bad token */
    @GetMapping("/validate")
    public ResponseEntity<Void> validate(@RequestHeader(HttpHeaders.AUTHORIZATION) String auth) {
        jwtService.validate(auth); // Call validate with the raw Authorization header, exceptions handled globally
        return ResponseEntity.ok().build();
    }
    // Removed /refresh endpoint
}
