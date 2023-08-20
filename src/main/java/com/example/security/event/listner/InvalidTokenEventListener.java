package com.example.security.event.listner;

import com.example.security.helper.LoggedOutJwtTokenCache;
import com.example.security.event.InvalidTokenEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class InvalidTokenEventListener implements ApplicationListener<InvalidTokenEvent> {
    private final LoggedOutJwtTokenCache tokenCache;

    public void onApplicationEvent(InvalidTokenEvent event) {
        String refreshToken = event.getRefreshToken();
        log.trace(
            "Log out success event received for user [{}] for RefreshToken [{}]",
            event.getUserEmail(), refreshToken
        );
        tokenCache.markLogoutEventForToken(event);
    }
}