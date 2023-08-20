package com.example.security.dto;

import com.example.entity.Session;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtAuthenticationResponse {
    private String accessToken;
    private String refreshToken;

    @JsonIgnore
    private List<Session> loggedOutSessions = new ArrayList<>();

    @JsonIgnore
    private String userName;
}