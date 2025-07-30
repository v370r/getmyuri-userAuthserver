package com.getmyuri.user_auth_service.service.security;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Component
public class FirebaseIdTokenProcessor {

    // private final UserDetailsService userDetailsService;

    // public FirebaseIdTokenProcessor(UserDetailsService userDetailsService) {
    // this.userDetailsService = userDetailsService;
    // }

    public FirebaseToken process(String idToken) {
        try {
            return FirebaseAuth.getInstance().verifyIdToken(idToken);
        } catch (FirebaseAuthException e) {
            throw new RuntimeException("Error processing Firebase ID token", e);
        }
    }
}
