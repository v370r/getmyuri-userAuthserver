package com.getmyuri.user_auth_service.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService; // Added
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor; // Added
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;

@Service
@RequiredArgsConstructor // Added
public class JwtService {

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration; // For access tokens

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    private final UserDetailsService userDetailsService; // Added

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> claims,
            UserDetails userDetails) {

        return buildToken(claims, userDetails, jwtExpiration);
    }

    private String generateToken(Map<String, Object> claims,
            UserDetails userDetails, long jwtExpiration) {

        return buildToken(claims, userDetails, jwtExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long jwtExpiration) {
        var authorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();
        return Jwts.builder().setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .claim("authorities", authorities)
                .signWith(getSignInKey())
                .compact();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public void validate(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new io.jsonwebtoken.MalformedJwtException("Authorization header is missing or does not start with Bearer string");
        }
        String token = authHeader.substring(7);
        try {
            // 1. Validate token structure, signature, and standard expiration.
            //    extractAllClaims will throw JwtException (e.g., ExpiredJwtException, MalformedJwtException, SignatureException) if invalid.
            Claims claims = extractAllClaims(token);
            String username = claims.getSubject();

            // 2. Check if username (subject) exists in the token.
            if (username == null) {
                throw new io.jsonwebtoken.JwtException("JWT token subject (username) is missing.");
            }

            // 3. Load user from database.
            //    This throws UsernameNotFoundException if user doesn't exist.
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // 4. Check user account status from UserDetails.
            if (!userDetails.isEnabled()) {
                throw new io.jsonwebtoken.DisabledException("User account is disabled.");
            }
            if (!userDetails.isAccountNonLocked()) {
                throw new io.jsonwebtoken.LockedException("User account is locked.");
            }
            // Not typically checked for API access with tokens, but can be included if required:
            // if (!userDetails.isAccountNonExpired()) {
            //     throw new io.jsonwebtoken.AccountExpiredException("User account has expired."); // Note: AccountExpiredException is a Spring Security exception
            // }
            // if (!userDetails.isCredentialsNonExpired()) {
            //     throw new io.jsonwebtoken.CredentialsExpiredException("User credentials have expired."); // Note: CredentialsExpiredException is a Spring Security exception
            // }

            // The token's own expiration is handled by extractAllClaims.
            // The username from the token has been used to load UserDetails, so they match by definition at this point.
            // Therefore, the core parts of `isTokenValid(token, userDetails)` are covered.

        } catch (org.springframework.security.core.userdetails.UsernameNotFoundException e) {
            // If user not found in DB, token is effectively invalid for this system.
            throw new io.jsonwebtoken.UnsupportedJwtException("User not found based on token subject: " + e.getMessage(), e);
        }
        // Other JwtExceptions (ExpiredJwtException, MalformedJwtException, SignatureException, etc.) from extractAllClaims
        // will propagate up and be handled by the global exception handler.
    }

    @PostConstruct
    public void validateProperties() { // TODO:// Implement logger
        System.out.println("JWT secret loaded: " + (secretKey != null));
        System.out.println("JWT expiration loaded: " + jwtExpiration);
    }

}
