package com.example.security.helper;

import com.example.security.event.InvalidTokenEvent;
import com.example.service.JwtService;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import net.jodah.expiringmap.ExpiringMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Component
@Slf4j
public class LoggedOutJwtTokenCache {
    private JwtService tokenService;

    private ExpiringMap<String, InvalidTokenEvent> tokenEventMap;

    @Autowired
    public void setTokenService(@Lazy JwtService tokenService) {
        this.tokenService = tokenService;
    }

    @PostConstruct
    void init() {
        this.tokenEventMap = ExpiringMap.builder()
            .variableExpiration()
            .maxSize(1000)
            .build();
    }

    public void markLogoutEventForToken(InvalidTokenEvent event) {
        String token = event.getAccessToken();
        if (tokenEventMap.containsKey(token)) {
            log.trace(String.format("Log out token for user [%s] is already present in the cache", event.getUserEmail()));
        } else {
            Date tokenExpiryDate = tokenService.getTokenExpiryFromExpiredJWT(token);
            if (tokenExpiryDate.before(new Date())) {
                log.trace("Token Already Expired, No Need To Cache It");
                return;
            }

            long ttlForToken = getTTLForToken(tokenExpiryDate);
            log.trace(
                "Logout token cache set for [{}] with a TTL of [{}] seconds. Token is due expiry at [{}]",
                event.getUserEmail(), ttlForToken, tokenExpiryDate
            );
            tokenEventMap.put(token, event, ttlForToken, TimeUnit.SECONDS);
        }
    }

    public InvalidTokenEvent getLogoutEventForToken(String token) {
        return tokenEventMap.get(token);
    }

    private long getTTLForToken(Date date) {
        long secondAtExpiry = date.toInstant().getEpochSecond();
        long secondAtLogout = Instant.now().getEpochSecond();
        return Math.max(0, secondAtExpiry - secondAtLogout);
    }
}