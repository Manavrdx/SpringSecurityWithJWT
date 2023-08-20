package com.example.security.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
public class SigninRequest {

    @NotBlank
    private String userName;

    @NotBlank
    private String password;
}