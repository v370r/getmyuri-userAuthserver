package com.getmyuri.user_auth_service.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    private final UserDetailsService userDetailsService;

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
        log.info("Generating token for user: {}", userDetails.getUsername());
        return buildToken(claims, userDetails, jwtExpiration);
    }

    private String generateToken(Map<String, Object> claims,
            UserDetails userDetails, long jwtExpiration) {

        return buildToken(claims, userDetails, jwtExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long jwtExpiration) {
        log.info("Building token for user: {}", userDetails.getUsername());
        var authorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();
        String token = Jwts.builder().setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .claim("authorities", authorities)
                .signWith(getSignInKey())
                .compact();
        log.info("Token built successfully for user: {}", userDetails.getUsername());
        return token;
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
        log.info("Validating token");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new io.jsonwebtoken.MalformedJwtException(
                    "Authorization header is missing or does not start with Bearer string");
        }
        String token = authHeader.substring(7);
        try {
            Claims claims = extractAllClaims(token);
            String username = claims.getSubject();

            if (username == null) {
                throw new io.jsonwebtoken.JwtException("JWT token subject (username) is missing.");
            }

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (!userDetails.isEnabled()) {
                throw new JwtException("User account is disabled.");
            }
            if (!userDetails.isAccountNonLocked()) {
                throw new JwtException("User account is locked.");
            }
            // Not typically checked for API access with tokens, but can be included if
            // required:
            // if (!userDetails.isAccountNonExpired()) {
            // throw new io.jsonwebtoken.AccountExpiredException("User account has
            // expired."); // Note: AccountExpiredException is a Spring Security exception
            // }
            // if (!userDetails.isCredentialsNonExpired()) {
            // throw new io.jsonwebtoken.CredentialsExpiredException("User credentials have
            // expired."); // Note: CredentialsExpiredException is a Spring Security
            // exception
            // }

            // The token's own expiration is handled by extractAllClaims.
            // The username from the token has been used to load UserDetails, so they match
            // by definition at this point.
            // Therefore, the core parts of `isTokenValid(token, userDetails)` are covered.

        } catch (org.springframework.security.core.userdetails.UsernameNotFoundException e) {
            // If user not found in DB, token is effectively invalid for this system.
            throw new io.jsonwebtoken.UnsupportedJwtException(
                    "User not found based on token subject: " + e.getMessage(), e);
        }
        // Other JwtExceptions (ExpiredJwtException, MalformedJwtException,
        // SignatureException, etc.) from extractAllClaims
        // will propagate up and be handled by the global exception handler.
    }

    @PostConstruct
    public void validateProperties() { // TODO:// Implement logger
        System.out.println("JWT secret loaded: " + (secretKey != null));
        System.out.println("JWT expiration loaded: " + jwtExpiration);
    }

}
