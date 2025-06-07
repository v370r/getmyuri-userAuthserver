package com.getmyuri.user_auth_service.service.auth;

import com.getmyuri.user_auth_service.common.constants.EmailConstants; // Import added
import com.getmyuri.user_auth_service.model.email.EmailTemplateName;
import com.getmyuri.user_auth_service.model.user.Token;
import com.getmyuri.user_auth_service.model.user.User;
import com.getmyuri.user_auth_service.repository.RoleRepository;
import com.getmyuri.user_auth_service.repository.TokenRepository;
import com.getmyuri.user_auth_service.repository.UserRepository;
import com.getmyuri.user_auth_service.service.JwtService;
import com.getmyuri.user_auth_service.service.email.EmailService;
import jakarta.mail.MessagingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock private TokenRepository tokenRepository;
    @Mock private UserRepository userRepository;
    @Mock private EmailService emailService;
    @Mock private RoleRepository roleRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private JwtService jwtService;

    @InjectMocks
    private AuthenticationService authenticationService;

    private User testUser;
    private Token testToken;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(1)
                .email("test@example.com")
                .firstname("Test")
                .lastname("User")
                .enabled(false)
                .build();

        testToken = Token.builder()
                .token("valid-token")
                .user(testUser)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .build();

        ReflectionTestUtils.setField(authenticationService, "activationUrl", "http://test.com/activate");
    }

    @Test
    void activateAccount_success() throws MessagingException {
        // Arrange
        when(tokenRepository.findByToken("valid-token")).thenReturn(Optional.of(testToken));
        when(userRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));

        // Act
        authenticationService.activateAccount("valid-token", "test@example.com");

        // Assert
        assertTrue(testUser.isEnabled());
        assertNotNull(testToken.getValidatedAt());
        verify(userRepository).save(testUser);
        verify(tokenRepository).save(testToken);
    }

    @Test
    void activateAccount_success_emailCaseInsensitive() throws MessagingException {
        // Arrange
        when(tokenRepository.findByToken("valid-token")).thenReturn(Optional.of(testToken));
        when(userRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));

        // Act
        authenticationService.activateAccount("valid-token", "Test@example.com");

        // Assert
        assertTrue(testUser.isEnabled());
        assertNotNull(testToken.getValidatedAt());
        verify(userRepository).save(testUser);
        verify(tokenRepository).save(testToken);
    }

    @Test
    void activateAccount_invalidEmail() {
        // Arrange
        when(tokenRepository.findByToken("valid-token")).thenReturn(Optional.of(testToken));

        // Act & Assert
        Exception exception = assertThrows(RuntimeException.class, () -> {
            authenticationService.activateAccount("valid-token", "wrong@example.com");
        });
        assertEquals("Invalid token or email", exception.getMessage());
        assertFalse(testUser.isEnabled());
        assertNull(testToken.getValidatedAt());
        verify(userRepository, never()).save(any(User.class));
        verify(tokenRepository, never()).save(any(Token.class));
    }

    @Test
    void activateAccount_invalidToken() {
        // Arrange
        when(tokenRepository.findByToken("invalid-token")).thenReturn(Optional.empty());

        // Act & Assert
        Exception exception = assertThrows(RuntimeException.class, () -> {
            authenticationService.activateAccount("invalid-token", "test@example.com");
        });
        assertEquals("Invalid token", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));
        verify(tokenRepository, never()).save(any(Token.class));
    }

    @Test
    void activateAccount_expiredToken_resendsEmail() throws MessagingException {
        // Arrange
        testToken.setExpiresAt(LocalDateTime.now().minusMinutes(1));
        testToken.setUser(testUser); // Ensure user is set in token for sendValidationEmail
        when(tokenRepository.findByToken("expired-token")).thenReturn(Optional.of(testToken));

        doNothing().when(emailService).sendEmail(
            anyString(), anyString(), any(EmailTemplateName.class), anyString(), anyString(), anyString()
        );

        // Act & Assert
        Exception exception = assertThrows(RuntimeException.class, () -> {
            authenticationService.activateAccount("expired-token", "test@example.com");
        });
        assertEquals("Activation token has expired. A new token is issued", exception.getMessage());

        verify(emailService).sendEmail(
            eq(testUser.getEmail()),
            eq(testUser.fullName()),
            eq(EmailTemplateName.ACTIVATE_ACCOUNT),
            eq("http://test.com/activate"),
            anyString(), // Verifies a string token is passed
            eq(EmailConstants.ACTIVATION_ACTIVATION) // Use the constant for the subject
        );
        assertFalse(testUser.isEnabled());
        assertNull(testToken.getValidatedAt());
        verify(userRepository, never()).save(testUser); // ensure the original user is not saved as enabled
                                                           // (a new one might be saved by generateAndSaveActivationToken, but not testUser)
        verify(tokenRepository, never()).save(testToken); // ensure original token is not saved as validated
    }
}
