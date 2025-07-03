package com.getmyuri.user_auth_service.model.user;

import java.security.Principal;
import java.time.LocalDate;
import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "_user")
@EntityListeners(AuditingEntityListener.class)
// Implementing Principal to potentially represent the authenticated user,
// details sourced from Keycloak token.
public class User implements Principal {

    @Id
    @GeneratedValue
    private Integer id; // Local DB ID

    @Column(unique = true, nullable = false)
    private String keycloakId; // Keycloak's 'sub' claim

    private String firstname;
    private String lastname;

    @Column(unique = true)
    private String email; // Can be sourced from Keycloak token

    private LocalDate dateOfBirth; // Optional: if needed locally

    // Removed: password, accountLocked, enabled, roles
    // UserDetails methods are removed as Keycloak handles authentication details.

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdDate;

    @LastModifiedDate
    @Column(insertable = false)
    private LocalDateTime lastModifiedData;

    @Override
    public String getName() {
        // This typically returns the username. Keycloak's 'preferred_username' or 'sub'
        // could be used.
        // If email is consistently the username in Keycloak, this is fine.
        // Otherwise, might need to be populated from the token's 'preferred_username'.
        return email;
    }

    public String fullName() {
        return firstname + " " + lastname;
    }

    // Consider if methods to populate User from JwtAuthenticationToken are needed,
    // or if this entity is primarily for storing supplementary local user data.
}
