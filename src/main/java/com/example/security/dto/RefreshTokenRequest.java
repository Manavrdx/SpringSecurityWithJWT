package com.example.security.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshTokenRequest {

    @NotBlank(message = "Access Token Is Mandatory")
    private String accessToken;

    @NotBlank(message = "Refresh Token Is Mandatory")
    private String refreshToken;
}
