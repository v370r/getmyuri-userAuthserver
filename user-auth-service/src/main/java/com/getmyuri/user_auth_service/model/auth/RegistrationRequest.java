package com.getmyuri.user_auth_service.model.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;



@Builder
@Data
public class RegistrationRequest {

    @NotBlank(message="Firstname is mandatory")
    private String firstname;
    
    @NotBlank(message="Lastname is mandatory")
    private String lastname;

    @Email(message="Email is not correctly formatted")
    @NotBlank(message="Email is mandatory")
    private String email;

    @NotBlank(message="Password is mandatory")
    @Size(min = 8, message="Password should be 8 or more characters")
    private String password;

}
