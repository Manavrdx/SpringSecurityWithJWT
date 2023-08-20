package com.example.service;

import com.example.enums.TokenType;
import com.example.properties.JwtTokenProperty;
import com.example.security.helper.LoggedOutJwtTokenCache;
import com.example.security.event.InvalidTokenEvent;
import com.github.f4b6a3.ulid.Ulid;
import com.github.f4b6a3.ulid.UlidCreator;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtService {
    private final JwtTokenProperty jwtTokenProperty;
    private final LoggedOutJwtTokenCache loggedOutJwtTokenCache;

    private Key signatureKey;

    @PostConstruct
    private void init() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtTokenProperty.getSignWithKey());
        signatureKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public Map<TokenType, String> generateBothToken(UserDetails userDetails) {
        Map<String, Object> extraClaims = new HashMap<>();

        String authorities = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        extraClaims.put(jwtTokenProperty.getAuthorityKey(), authorities);
        return generateBothToken(extraClaims, userDetails);
    }

    public boolean isValidToken(String token) {
        boolean validationResult = false;
        try {
            Jwts.parserBuilder().setSigningKey(signatureKey).build().parse(token);
            validateTokenIsNotForALoggedOutDevice(token);
            validationResult = true;
        } catch (SecurityException e) {
            log.error(
                "Invalid JWT signature:: {}{}, Token Was:: {}",
                e.getMessage(), System.lineSeparator(), token
            );
        } catch (MalformedJwtException e) {
            log.error(
                "MalformedJwt:: {}{}, Token Was:: {}",
                e.getMessage(), System.lineSeparator(), token
            );
        } catch (ExpiredJwtException e) {
            log.debug(
                "JWT token is expired: {}{}, Token Is:: {}",
                e.getMessage(), System.lineSeparator(), token
            );
        } catch (UnsupportedJwtException e) {
            log.error(
                "UnsupportedJwtException:: {}{}, Token Was:: {}",
                e.getMessage(), System.lineSeparator(), token
            );
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty:: {}", e.getMessage());
        }
        return validationResult;
    }

    private Map<TokenType, String> generateBothToken(Map<String, Object> extraClaims,
                                                     UserDetails userDetails) {

        long currentTimeMillis = System.currentTimeMillis();
        String accessToken = getAccessToken(extraClaims, userDetails, currentTimeMillis);

        long refreshTokenExpirationInMilliSeconds = jwtTokenProperty.refreshTokenExpirationInMilliSeconds();
        Date refreshTokenWillExpireOn = new Date(currentTimeMillis + refreshTokenExpirationInMilliSeconds);
        Ulid refreshToken = UlidCreator.getUlid(refreshTokenWillExpireOn.getTime());

        return Map.of(
            TokenType.ACCESS_TOKEN, accessToken,
            TokenType.REFRESH_TOKEN, refreshToken.toString()
        );
    }

    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> extraClaims = new HashMap<>();

        String authorities = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        extraClaims.put(jwtTokenProperty.getAuthorityKey(), authorities);
        return getAccessToken(extraClaims, userDetails, System.currentTimeMillis());
    }

    private String getAccessToken(Map<String, Object> extraClaims, UserDetails userDetails,
                                  long currentTimeMillis) {
        final long bearerTokenExpirationInMilliSeconds =
                jwtTokenProperty.bearerTokenExpirationInMilliSeconds();
        final Date issuedAt = new Date(currentTimeMillis);
        final Date willExpireOn = new Date(
            currentTimeMillis + bearerTokenExpirationInMilliSeconds
        );

        return Jwts.builder().setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuer(jwtTokenProperty.getIssuedBy())
                .setIssuedAt(issuedAt)
                .setExpiration(willExpireOn)
                .signWith(signatureKey, jwtTokenProperty.signatureAlgorithm())
                .compact();
    }

    private Claims extractAllClaims(String token) throws ExpiredJwtException, UnsupportedJwtException,
            MalformedJwtException, SecurityException, IllegalArgumentException {
        return Jwts.parserBuilder()
                .setSigningKey(signatureKey).build()
                .parseClaimsJws(token)
                .getBody();
    }

    public UsernamePasswordAuthenticationToken createAuthentication(String token) {
        Claims claims = extractAllClaims(token);

        String scopesString = claims.get(jwtTokenProperty.getAuthorityKey()).toString();
        String[] authStrings = scopesString.split(",");

        Collection<? extends GrantedAuthority> authorities = Arrays.stream(authStrings)
                .map(SimpleGrantedAuthority::new)
                .toList();

        String subject = claims.getSubject();
        org.springframework.security.core.userdetails.User principal =
                new User(subject, "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    public Date getTokenExpiryFromJWT(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(signatureKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getExpiration();
    }

    private void validateTokenIsNotForALoggedOutDevice(String authToken) {
        InvalidTokenEvent previouslyLoggedOutEvent = loggedOutJwtTokenCache.getLogoutEventForToken(authToken);
        if (previouslyLoggedOutEvent != null) {
            String userEmail = previouslyLoggedOutEvent.getUserEmail();
            Date logoutEventDate = previouslyLoggedOutEvent.getEventTime();
            String errorMessage = String.format(
                "Token corresponds to an already logged out user [%s] at [%s]. " +
                "Please login again", userEmail, logoutEventDate
            );
            throw new IllegalStateException(errorMessage);
        }
    }

    public String getUserNameFromExpiredJWT(String token) {
        try{
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(signatureKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return claims.getSubject();
        } catch(ExpiredJwtException e) {
            Claims claims = e.getClaims();
            return claims.getSubject();
        }
    }

    public Date getTokenExpiryFromExpiredJWT(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(signatureKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return claims.getExpiration();
        } catch (ExpiredJwtException e) {
            Claims claims = e.getClaims();
            return claims.getExpiration();
        }
    }
}