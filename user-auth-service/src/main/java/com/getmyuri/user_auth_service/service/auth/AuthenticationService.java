package com.getmyuri.user_auth_service.service.auth;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;

import org.apache.coyote.http11.filters.SavedRequestInputFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.getmyuri.user_auth_service.common.constants.Constants;
import static com.getmyuri.user_auth_service.common.constants.EmailConstants.ACTIVATION_ACTIVATION;
import static com.getmyuri.user_auth_service.common.constants.EmailConstants.DIGITS;

import com.getmyuri.user_auth_service.model.auth.AuthenticationRequest;
import com.getmyuri.user_auth_service.model.auth.AuthenticationResponse;
import com.getmyuri.user_auth_service.model.auth.RegistrationRequest;
import com.getmyuri.user_auth_service.model.email.EmailTemplateName;
import com.getmyuri.user_auth_service.model.user.Token;
import com.getmyuri.user_auth_service.model.user.User;
import com.getmyuri.user_auth_service.repository.RoleRepository;
import com.getmyuri.user_auth_service.repository.TokenRepository;
import com.getmyuri.user_auth_service.repository.UserRepository;
import com.getmyuri.user_auth_service.service.JwtService;
import com.getmyuri.user_auth_service.service.email.EmailService;

import jakarta.mail.MessagingException;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository tokenRepository;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;
    private final JwtService jwtService;

    @Value("${application.mailing.frontend.activation-url}")
    private String activationUrl;

    public void register(RegistrationRequest request) throws MessagingException {
        var userRole = roleRepository.findByName(Constants.USER)
                .orElseThrow(() -> new IllegalStateException("ROLE USER was not initialized"));
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .accountLocked(false)
                .enabled(false)
                .roles(List.of(userRole))
                .build();
        userRepository.save(user);
        sendValidationEmail(user);
    }

    private void sendValidationEmail(User user) throws MessagingException {
        var newToken = generateAndSaveActivationToken(user);
        emailService.sendEmail(user.getEmail(),
                user.fullName(),
                EmailTemplateName.ACTIVATE_ACCOUNT,
                activationUrl, newToken, ACTIVATION_ACTIVATION);

    }

    private String generateAndSaveActivationToken(User user) {
        String generatedToken = generateActivationCode(6);
        var token = Token.builder()
                .token(generatedToken)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .user(user)
                .build();
        tokenRepository.save(token);
        return generatedToken;
    }

    private String generateActivationCode(int length) {
        String characters = DIGITS;
        StringBuilder numberGen = new StringBuilder();
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(characters.length());
            numberGen.append(characters.charAt(randomIndex));
        }
        return numberGen.toString();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        var auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getEmail(), request.getPassword()));
        var claims = new HashMap<String, Object>();
        var user = ((User) auth.getPrincipal());
        claims.put("fullName", user.fullName());
        var jwtToken = jwtService.generateToken(claims, user);
        return AuthenticationResponse.builder().token(jwtToken)
                .build();

    }

    @Transactional
    public void activateAccount(String token, String email) throws MessagingException {
        Token savedToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        User userFromToken = savedToken.getUser();
        if (userFromToken == null || !email.equalsIgnoreCase(userFromToken.getEmail())) {
            throw new RuntimeException("Invalid token or email");
        }

        if (LocalDateTime.now().isAfter(savedToken.getExpiresAt())) {
            sendValidationEmail(savedToken.getUser());
            throw new RuntimeException("Activation token has expired. A new token is issued");
        }

        var user = userRepository.findById(userFromToken.getId())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        user.setEnabled(Boolean.TRUE);
        userRepository.save(user);
        savedToken.setValidatedAt(LocalDateTime.now());
        tokenRepository.save(savedToken);

    }

}
