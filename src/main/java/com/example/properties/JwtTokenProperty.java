package com.example.properties;

import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
@Validated
public class JwtTokenProperty {

    @NotBlank
    private String signatureAlgorithm = "HS256";

    @NotBlank
    private String signWithKey;

    @NotBlank
    private String issuedBy;

    private String authorityKey = "scopes";

    @Min(1)
    @NotNull
    private Integer allowedSessionCount = 1;

    private boolean autoLogoutFromOtherDeviceOnOverflowSessionCount = true;

    @NotNull
    private Duration bearerTokenExpiration = Duration.of(5, ChronoUnit.MINUTES);

    @NotNull
    private Duration refreshTokenExpiration = Duration.of(30, ChronoUnit.MINUTES);

    public long bearerTokenExpirationInMilliSeconds() {
        return bearerTokenExpiration.toMillis();
    }

    public long refreshTokenExpirationInMilliSeconds() {
        return refreshTokenExpiration.toMillis();
    }

    public SignatureAlgorithm signatureAlgorithm() {
        return SignatureAlgorithm.valueOf(signatureAlgorithm);
    }
}
