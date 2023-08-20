package com.example.security.dto;


import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LogOutRequest {

    @NotBlank(message = "Access Token Is Mandatory")
    private String accessToken;

    @NotBlank(message = "Refresh Token Is Mandatory")
    private String refreshToken;
}
