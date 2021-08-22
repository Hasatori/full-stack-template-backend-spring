package com.example.fullstacktemplate.payload;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

@Getter
@Setter
public class LoginRequest {
    @NotBlank(message = "email.blank")
    @Email(message = "email.invalidFormat")
    private String email;

    @NotBlank(message = "password.blank")
    private String password;
    private Boolean rememberMe;
}